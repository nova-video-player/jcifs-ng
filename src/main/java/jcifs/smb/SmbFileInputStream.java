/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb;


import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.MalformedURLException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.SmbConstants;
import jcifs.SmbFileHandle;
import jcifs.internal.smb1.com.SmbComReadAndX;
import jcifs.internal.smb1.com.SmbComReadAndXResponse;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;
import jcifs.util.transport.TransportException;


/**
 * This InputStream can read bytes from a file on an SMB file server. Offsets are 64 bits.
 */
public class SmbFileInputStream extends InputStream {

    private static final Logger log = LoggerFactory.getLogger(SmbFileInputStream.class);

    private SmbFileHandleImpl handle;
    private long fp;
    private int readSize, readSizeFile, openFlags, access, sharing;
    private byte[] tmp = new byte[1];

    SmbFile file;

    private boolean largeReadX;

    private final boolean unsharedFile;

    private boolean smb2;

    // single-slot read-ahead pipeline, used for SMB2 filesystem reads only (see readPipelined).
    // While the caller consumes raBuf, the next block is already being fetched in the
    // background, overlapping network round-trip latency with the caller's processing time -
    // this mirrors the equivalent read-ahead done by the smbj library. The prefetch is run on a
    // short-lived daemon thread spawned per outstanding request (see submitPrefetch); since at
    // most one prefetch is ever in flight at a time there is no benefit to a persistent
    // executor, and this avoids any thread lingering for the lifetime of the stream.
    // raEof is sticky for the lifetime of the stream once a chunk read (sync or prefetched)
    // comes back empty - this class has no support for repositioning past a known EOF, so once
    // observed it will always be the true end of the readable range.
    private byte[] raBuf;
    private int raLen;
    private int raPos;
    private boolean raEof;
    private Future<byte[]> raPending;


    /**
     * @param url
     * @param tc
     *            context to use
     * @throws SmbException
     * @throws MalformedURLException
     */
    @SuppressWarnings ( "resource" )
    public SmbFileInputStream ( String url, CIFSContext tc ) throws SmbException, MalformedURLException {
        this(new SmbFile(url, tc), 0, SmbConstants.O_RDONLY, SmbConstants.DEFAULT_SHARING, true);
    }


    /**
     * Creates an {@link java.io.InputStream} for reading bytes from a file on
     * an SMB server represented by the {@link jcifs.smb.SmbFile} parameter. See
     * {@link jcifs.smb.SmbFile} for a detailed description and examples of
     * the smb URL syntax.
     *
     * @param file
     *            An <code>SmbFile</code> specifying the file to read from
     * @throws SmbException
     */
    public SmbFileInputStream ( SmbFile file ) throws SmbException {
        this(file, 0, SmbConstants.O_RDONLY, SmbConstants.DEFAULT_SHARING, false);
    }


    SmbFileInputStream ( SmbFile file, int openFlags, int access, int sharing, boolean unshared ) throws SmbException {
        this.file = file;
        this.unsharedFile = unshared;
        this.openFlags = openFlags;
        this.access = access;
        this.sharing = sharing;

        try ( SmbTreeHandleInternal th = file.ensureTreeConnected() ) {
            this.smb2 = th.isSMB2();
            if ( file.getType() != SmbConstants.TYPE_NAMED_PIPE ) {
                try ( SmbFileHandle h = ensureOpen() ) {}
                this.openFlags &= ~ ( SmbConstants.O_CREAT | SmbConstants.O_TRUNC );
            }

            init(th);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    /**
     * @throws SmbException
     * 
     */
    SmbFileInputStream ( SmbFile file, SmbTreeHandleImpl th, SmbFileHandleImpl fh ) throws SmbException {
        this.file = file;
        this.handle = fh;
        this.unsharedFile = false;
        this.smb2 = th.isSMB2();
        try {
            init(th);
        }
        catch ( CIFSException e ) {
            throw SmbException.wrap(e);
        }
    }


    /**
     * @param f
     * @param th
     * @throws SmbException
     */
    private void init ( SmbTreeHandleInternal th ) throws CIFSException {
        if ( this.smb2 ) {
            this.readSize = th.getReceiveBufferSize();
            this.readSizeFile = th.getReceiveBufferSize();
            return;
        }

        this.readSize = Math.min(th.getReceiveBufferSize() - 70, th.getMaximumBufferSize() - 70);

        if ( th.hasCapability(SmbConstants.CAP_LARGE_READX) ) {
            this.largeReadX = true;
            this.readSizeFile = Math.min(th.getConfig().getReceiveBufferSize() - 70, th.areSignaturesActive() ? 0xFFFF - 70 : 0xFFFFFF - 70);
            log.debug("Enabling LARGE_READX with " + this.readSizeFile);
        }
        else {
            log.debug("LARGE_READX disabled");
            this.readSizeFile = this.readSize;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Negotiated file read size is " + this.readSizeFile);
        }
    }


    /**
     * Ensures that the file descriptor is openend
     * 
     * @throws CIFSException
     */
    public void open () throws CIFSException {
        try ( SmbFileHandleImpl fh = ensureOpen() ) {}
    }


    /**
     * @param file
     * @param openFlags
     * @return
     * @throws SmbException
     */
    synchronized SmbFileHandleImpl ensureOpen () throws CIFSException {
        if ( this.handle == null || !this.handle.isValid() ) {
            // one extra acquire to keep this open till the stream is released
            if ( this.file instanceof SmbNamedPipe ) {
                this.handle = this.file.openUnshared(
                    SmbConstants.O_EXCL,
                    ( (SmbNamedPipe) this.file ).getPipeType() & 0xFF0000,
                    this.sharing,
                    SmbConstants.ATTR_NORMAL,
                    0);
            }
            else {
                this.handle = this.file.openUnshared(this.openFlags, this.access, this.sharing, SmbConstants.ATTR_NORMAL, 0).acquire();
            }
            return this.handle;
        }
        return this.handle.acquire();
    }


    protected static IOException seToIoe ( SmbException se ) {
        IOException ioe = se;
        Throwable root = se.getCause();
        if ( root instanceof TransportException ) {
            ioe = (TransportException) root;
            root = ( (TransportException) ioe ).getCause();
        }
        if ( root instanceof InterruptedException ) {
            ioe = new InterruptedIOException(root.getMessage());
            ioe.initCause(root);
        }
        return ioe;
    }


    /**
     * Closes this input stream and releases any system resources associated with the stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public void close () throws IOException {
        try {
            SmbFileHandleImpl h = this.handle;
            if ( h != null ) {
                h.close();
            }
        }
        catch ( SmbException se ) {
            throw seToIoe(se);
        }
        finally {
            this.tmp = null;
            this.handle = null;
            // Any outstanding read-ahead prefetch (see submitPrefetch) holds its own pinned
            // acquire()'d reference to the file handle/tree, independent of this.handle - it is
            // left to finish on its own background thread and release that reference itself
            // when done; we only drop our local view of it and discard its eventual result.
            this.raBuf = null;
            this.raPending = null;
            if ( this.unsharedFile ) {
                this.file.close();
            }
        }
    }


    /**
     * Reads a byte of data from this input stream.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read () throws IOException {
        // need oplocks to cache otherwise use BufferedInputStream
        if ( read(this.tmp, 0, 1) == -1 ) {
            return -1;
        }
        return this.tmp[ 0 ] & 0xFF;
    }


    /**
     * Reads up to b.length bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read ( byte[] b ) throws IOException {
        return read(b, 0, b.length);
    }


    /**
     * Reads up to len bytes of data from this input stream into an array of bytes.
     *
     * @throws IOException
     *             if a network error occurs
     */

    @Override
    public int read ( byte[] b, int off, int len ) throws IOException {
        return readDirect(b, off, len);
    }


    /**
     * Reads up to len bytes of data from this input stream into an array of bytes.
     * 
     * @param b
     * @param off
     * @param len
     * @return number of bytes read
     *
     * @throws IOException
     *             if a network error occurs
     */
    public int readDirect ( byte[] b, int off, int len ) throws IOException {
        if ( len <= 0 ) {
            return 0;
        }
        if ( this.tmp == null ) {
            throw new IOException("Bad file descriptor");
        }
        // ensure file is open
        try ( SmbFileHandleImpl fd = ensureOpen();
              SmbTreeHandleImpl th = fd.getTree() ) {
            int type = this.file.getType();
            if ( th.isSMB2() && type == SmbConstants.TYPE_FILESYSTEM ) {
                return readPipelined(fd, th, b, off, len);
            }
            return readDirectLegacy(fd, th, type, b, off, len);
        }
    }


    /**
     * Unbuffered single request/response read, used for SMB1 and for non-filesystem SMB2
     * resources (e.g. named pipes) where read-ahead pipelining is not applicable/safe.
     */
    private int readDirectLegacy ( SmbFileHandleImpl fd, SmbTreeHandleImpl th, int type, byte[] b, int off, int len ) throws IOException {
        long start = this.fp;

        /*
         * Read AndX Request / Response
         */

        if ( log.isTraceEnabled() ) {
            log.trace("read: fid=" + fd + ",off=" + off + ",len=" + len);
        }

        SmbComReadAndXResponse response = new SmbComReadAndXResponse(th.getConfig(), b, off);

        int r, n;
        int blockSize = ( type == SmbConstants.TYPE_FILESYSTEM ) ? this.readSizeFile : this.readSize;
        do {
                r = len > blockSize ? blockSize : len;

                if ( log.isTraceEnabled() ) {
                    log.trace("read: len=" + len + ",r=" + r + ",fp=" + this.fp + ",b.length=" + b.length);
                }

                try {

                    if ( th.isSMB2() ) {
                        Smb2ReadRequest request = new Smb2ReadRequest(th.getConfig(), fd.getFileId(), b, off);
                        request.setOffset(type == SmbConstants.TYPE_NAMED_PIPE ? 0 : this.fp);
                        request.setReadLength(r);
                        request.setRemainingBytes(len - r);

                        try {
                            Smb2ReadResponse resp = th.send(request, RequestParam.NO_RETRY);
                            n = resp.getDataLength();
                        }
                        catch ( SmbException e ) {
                            if ( e.getNtStatus() == 0xC0000011 ) {
                                log.debug("Reached end of file", e);
                                n = -1;
                            }
                            else {
                                throw e;
                            }
                        }
                        if ( n <= 0 ) {
                            return (int) ( ( this.fp - start ) > 0L ? this.fp - start : -1 );
                        }
                        this.fp += n;
                        off += n;
                        len -= n;
                        continue;
                    }

                    SmbComReadAndX request = new SmbComReadAndX(th.getConfig(), fd.getFid(), this.fp, r, null);
                    if ( type == SmbConstants.TYPE_NAMED_PIPE ) {
                        request.setMinCount(1024);
                        request.setMaxCount(1024);
                        request.setRemaining(1024);
                    }
                    else if ( this.largeReadX ) {
                        request.setMaxCount(r & 0xFFFF);
                        request.setOpenTimeout( ( r >> 16 ) & 0xFFFF);
                    }
                    th.send(request, response, RequestParam.NO_RETRY);
                    n = response.getDataLength();
                }
                catch ( SmbException se ) {
                    if ( type == SmbConstants.TYPE_NAMED_PIPE && se.getNtStatus() == NtStatus.NT_STATUS_PIPE_BROKEN ) {
                        return -1;
                    }
                    throw seToIoe(se);
                }
                if ( n <= 0 ) {
                    return (int) ( ( this.fp - start ) > 0L ? this.fp - start : -1 );
                }
                this.fp += n;
                len -= n;
                response.adjustOffset(n);
            }
        while ( len > blockSize && n == r );
        // this used to be len > 0, but this is BS:
        // - InputStream.read gives no such guarantee
        // - otherwise the caller would need to figure out the block size, or otherwise might end up with very small
        // reads
        return (int) ( this.fp - start );
    }


    /**
     * Pipelined read for SMB2 filesystem resources: serves data from a single-slot read-ahead
     * buffer and keeps the following block prefetching in the background while the caller
     * consumes/copies the current one, overlapping network round-trip latency with local
     * processing (mirrors the read-ahead done by the smbj library).
     */
    private int readPipelined ( SmbFileHandleImpl fd, SmbTreeHandleImpl th, byte[] b, int off, int len ) throws IOException {
        if ( this.raEof ) {
            return -1;
        }

        int blockSize = this.readSizeFile;

        if ( this.raBuf == null ) {
            // snapshot into a local var before clearing the field: awaitPending() takes it as a
            // parameter rather than re-reading this.raPending itself, so a concurrent close()
            // clearing the field afterwards cannot turn this into a null-pointer access
            Future<byte[]> pending = this.raPending;
            this.raPending = null;
            byte[] chunk;
            if ( pending != null ) {
                chunk = awaitPending(pending);
            }
            else {
                // Size this synchronous, non-prefetched fetch against the file size observed at
                // open time rather than always requesting a full negotiated block:
                // for a small file (e.g. an NFO/thumbnail during a network share scan/scrape)
                // this avoids allocating a full blockSize (potentially 1MB+) buffer just to
                // discard almost all of it. Background prefetches below remain sized to a full
                // block, since they are only ever triggered once a full block has actually been
                // observed (see the raLen == blockSize check below).
                //
                // The size observed at open time is only ever used here to size the request when
                // there is confidently more data (primeFetchSize() > 0) - it is never used to
                // infer EOF. The stream is opened with FILE_SHARE_WRITE, so a concurrent writer
                // can extend the file after open; when the hint says nothing more should be left
                // (primeFetchSize() <= 0) a real request is still sent to the server sized to a
                // full block, and EOF is only ever latched below based on what the server itself
                // reports (chunk == null), never based on the hint alone.
                int primeSize = primeFetchSize(fd, blockSize);
                int fetchSize = ( primeSize > 0 ) ? primeSize : blockSize;
                chunk = readChunk0(fd, th, this.fp, fetchSize);
            }
            if ( chunk == null ) {
                this.raEof = true;
                return -1;
            }
            this.raBuf = chunk;
            this.raPos = 0;
            this.raLen = chunk.length;
        }

        // Only prefetch ahead of a full block: a short read (raLen < blockSize) means the
        // server had less than a full block available at that offset, which is a strong (though
        // not absolute) signal that EOF is at or very near the position just served - the same
        // assumption readDirectLegacy's own loop makes via its "n == r" continuation check.
        // Submitting a prefetch there would, for the common case of many small files (e.g.
        // during a network share scan/scrape touching lots of small NFO/thumbnail files), cost
        // an extra SMB2 round trip plus a wasted blockSize-sized allocation and background
        // thread per file, for a read-ahead that is very unlikely to pay off since there is
        // usually no further data to hide latency behind. If more data does turn out to be
        // available after all, the next call simply falls back to a synchronous fetch once
        // raBuf is exhausted, exactly as it would without pipelining.
        if ( this.raPending == null && this.raLen == blockSize ) {
            long nextFp = this.fp + ( this.raLen - this.raPos );
            this.raPending = submitPrefetch(fd, nextFp, blockSize);
        }

        int avail = this.raLen - this.raPos;
        int n = Math.min(avail, len);
        System.arraycopy(this.raBuf, this.raPos, b, off, n);
        this.raPos += n;
        this.fp += n;
        if ( this.raPos >= this.raLen ) {
            this.raBuf = null;
        }
        return n;
    }


    /**
     * Computes how large a synchronous no-buffer/no-pending fetch for this stream/position
     * should be, using the file size observed when the handle was opened
     * ({@link SmbFileHandleImpl#getInitialSize()}) as a hint to avoid over-allocating for small
     * files. This is called for every such fetch, not just the very first one in the stream's
     * life (e.g. also after a {@link #skip(long)}-triggered drain, or whenever the previous
     * chunk was a short read so no prefetch was queued).
     * <p>
     * This is only a sizing hint and must never be used to infer EOF: the file may have grown
     * since the handle was opened (it is opened with {@code FILE_SHARE_WRITE}, so a concurrent
     * writer can extend it), in which case a non-positive result here only means the hint has
     * nothing left to offer - the caller still issues a real request to the server sized to a
     * full block in that case, and only the server's own response can establish EOF.
     *
     * @return the number of bytes to request, sized to the remaining bytes reported at open
     *         time, or {@code <= 0} if the current position is already at or past the size
     *         observed at open time (the caller must still fetch a full block from the server
     *         in that case rather than assuming EOF)
     */
    private int primeFetchSize ( SmbFileHandleImpl fd, int blockSize ) {
        long size = fd.getInitialSize();
        long remaining = size - this.fp;
        if ( remaining <= 0 ) {
            // covers both a genuinely empty file (size == 0, fp == 0) and any position already
            // at/past the size observed at open time
            return 0;
        }
        return (int) Math.min(blockSize, remaining);
    }


    private byte[] awaitPending ( Future<byte[]> pending ) throws IOException {
        try {
            return pending.get();
        }
        catch ( InterruptedException e ) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting for read-ahead");
        }
        catch ( ExecutionException e ) {
            Throwable cause = e.getCause();
            if ( cause instanceof IOException ) {
                throw (IOException) cause;
            }
            throw new IOException("Read-ahead failed", cause);
        }
    }


    /**
     * Kicks off a background prefetch of the block starting at {@code atFp}. The file handle is
     * pinned via a ref-counted {@link SmbFileHandleImpl#acquire()} *before* returning to the
     * caller, and the tree is likewise acquired lazily by the background thread off of that
     * pinned handle - the prefetch never calls {@link #ensureOpen()}, so it can never reopen a
     * new handle after the stream has been closed. Closing the stream drops the stream's own
     * reference immediately (see {@link #close()}), but this pinned reference keeps the
     * underlying SMB handle/tree alive on the server until the prefetch itself finishes and
     * releases it in its {@code finally} block, whatever the outcome.
     */
    private Future<byte[]> submitPrefetch ( SmbFileHandleImpl fd, final long atFp, final int blockSize ) {
        final SmbFileHandleImpl pinnedFd = fd.acquire();
        FutureTask<byte[]> task = new FutureTask<>(new Callable<byte[]>() {

            @Override
            public byte[] call () throws IOException {
                try ( SmbTreeHandleImpl pinnedTh = pinnedFd.getTree() ) {
                    return readChunk0(pinnedFd, pinnedTh, atFp, blockSize);
                }
                finally {
                    try {
                        pinnedFd.release();
                    }
                    catch ( CIFSException e ) {
                        log.debug("Failed to release read-ahead file handle", e);
                    }
                }
            }
        });
        Thread t = new Thread(task, "jcifs-readahead-" + System.identityHashCode(this));
        t.setDaemon(true);
        t.start();
        return task;
    }


    private byte[] readChunk0 ( SmbFileHandleImpl fd, SmbTreeHandleImpl th, long atFp, int blockSize ) throws IOException {
        byte[] chunk = new byte[blockSize];
        Smb2ReadRequest request = new Smb2ReadRequest(th.getConfig(), fd.getFileId(), chunk, 0);
        request.setOffset(atFp);
        request.setReadLength(blockSize);
        request.setRemainingBytes(0);

        int n;
        try {
            Smb2ReadResponse resp = th.send(request, RequestParam.NO_RETRY);
            n = resp.getDataLength();
        }
        catch ( SmbException e ) {
            if ( e.getNtStatus() == 0xC0000011 ) {
                log.debug("Reached end of file", e);
                return null;
            }
            throw seToIoe(e);
        }
        if ( n <= 0 ) {
            return null;
        }
        if ( n == chunk.length ) {
            return chunk;
        }
        byte[] exact = new byte[n];
        System.arraycopy(chunk, 0, exact, 0, n);
        return exact;
    }


    /**
     * This stream class is unbuffered. Therefore this method will always
     * return 0 for streams connected to regular files. However, a
     * stream created from a Named Pipe this method will query the server using a
     * "peek named pipe" operation and return the number of available bytes
     * on the server.
     */
    @Override
    public int available () throws IOException {
        return 0;
    }


    /**
     * Skip n bytes of data on this stream. This does not issue any new IO with the server.
     * Unlink <tt>InputStream</tt> value less than the one provided will not be returned if it
     * exceeds the end of the file (if this is a problem let us know).
     */
    @Override
    public long skip ( long n ) throws IOException {
        if ( n <= 0 ) {
            return 0;
        }
        if ( this.raBuf != null && this.raPos + n <= this.raLen ) {
            // still within the currently buffered read-ahead block, no need to discard it
            this.raPos += (int) n;
            this.fp += n;
            return n;
        }
        // outside buffered data (or nothing buffered): the buffered block, if any, is stale and
        // dropped. Any outstanding prefetch is drained (not force-cancelled - interrupting it
        // could abort an in-flight socket write/read in an undefined state) before its
        // reference is dropped, so that only one read-ahead is ever in flight for this stream
        // at a time; without this, repeated skip()+read() could otherwise pile up multiple
        // concurrent background requests. This does not itself issue any new request to the
        // server, it only waits for one that was already in flight.
        this.raBuf = null;
        drainPending();
        this.fp += n;
        return n;
    }


    /**
     * Waits for any currently outstanding read-ahead prefetch to finish and discards its
     * result/error, without submitting any new request. Used to preserve the invariant that at
     * most one prefetch is ever in flight for this stream, when the buffered read-ahead is
     * abandoned (see {@link #skip(long)}) rather than being naturally consumed by
     * {@link #readPipelined}.
     * <p>
     * Waits uninterruptibly: the prefetch must be known to have finished before this method
     * returns, in order to guarantee the field is not cleared while it's still outstanding, so an
     * interrupt received while waiting is recorded and re-applied to the calling thread only
     * once the drain itself is complete, rather than aborting the wait early.
     */
    private void drainPending () {
        Future<byte[]> pending = this.raPending;
        this.raPending = null;
        if ( pending == null ) {
            return;
        }
        boolean interrupted = false;
        try {
            while ( true ) {
                try {
                    pending.get();
                    break;
                }
                catch ( InterruptedException e ) {
                    interrupted = true;
                }
            }
        }
        catch ( ExecutionException e ) {
            log.debug("Discarding failed stale read-ahead", e);
        }
        finally {
            if ( interrupted ) {
                Thread.currentThread().interrupt();
            }
        }
    }

}

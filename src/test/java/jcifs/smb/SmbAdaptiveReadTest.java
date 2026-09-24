/* Copyright (C) Courville Software 2026
 * Licensed under the GNU Lesser General Public License, version 2.1 or later.
 */
package jcifs.smb;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;
import jcifs.internal.util.SMBUtil;
import jcifs.util.transport.Request;

/** Real request encoding, credit accounting and file readers against a fake SMB2 peer. */
public class SmbAdaptiveReadTest {
    private static final int CREDIT = 65536;
    private static final int MIB = 16 * CREDIT;

    private static Field field ( Class<?> type, String name ) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static byte content ( long offset ) {
        return (byte) ( ( offset * 31 ) ^ ( offset >> 8 ) ^ ( offset >> 17 ) );
    }

    private static final class Peer extends SmbTransportImpl {
        final Configuration config;
        final Semaphore permits;
        final List<Long> ids = Collections.synchronizedList(new ArrayList<Long>());
        volatile int grant = -1;
        volatile long fileSize = 10L * MIB + 137;
        volatile int lastLength;
        volatile CountDownLatch entered;
        volatile CountDownLatch respond;

        Peer ( int credits ) throws Exception {
            this(context(), credits);
        }

        private Peer ( CIFSContext context, int credits ) throws Exception {
            super(context, null, 445, null, 0, false);
            this.config = context.getConfig();
            field(SmbTransportImpl.class, "smb2").setBoolean(this, true);
            field(SmbTransportImpl.class, "largeMtu").setBoolean(this, true);
            this.permits = (Semaphore) field(SmbTransportImpl.class, "credits").get(this);
            this.permits.drainPermits();
            this.permits.release(credits);
        }

        private static CIFSContext context () {
            Configuration config = mock(Configuration.class);
            when(config.getMaximumBufferSize()).thenReturn(CREDIT);
            when(config.getResponseTimeout()).thenReturn(1000);
            CIFSContext context = mock(CIFSContext.class);
            when(context.getConfig()).thenReturn(config);
            return context;
        }

        @Override
        public boolean isDisconnected () {
            return false;
        }

        @Override
        protected void doSend ( Request request ) throws IOException {
            Smb2ReadRequest read = (Smb2ReadRequest) request;
            byte[] wire = new byte[read.size()];
            read.encode(wire, 0);
            int length = SMBUtil.readInt4(wire, 68);
            int charge = SMBUtil.readInt2(wire, 6);
            assertEquals(( length - 1 ) / CREDIT + 1, charge);
            assertEquals(charge, read.getCreditCost());
            this.lastLength = length;
            synchronized ( this.ids ) {
                for ( int i = 0; i < charge; i++ ) {
                    long id = read.getMid() + i;
                    assertFalse("Message ID reused: " + id, this.ids.contains(id));
                    this.ids.add(id);
                }
            }
            if ( this.entered != null ) {
                this.entered.countDown();
                try {
                    assertTrue(this.respond.await(5, TimeUnit.SECONDS));
                }
                catch ( InterruptedException e ) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException();
                }
            }
            long offset = SMBUtil.readInt8(wire, 72);
            int count = (int) Math.max(0, Math.min(length, this.fileSize - offset));
            byte[] reply = new byte[80 + count];
            reply[0] = (byte) 0xFE;
            reply[1] = 'S'; reply[2] = 'M'; reply[3] = 'B';
            SMBUtil.writeInt2(64, reply, 4);
            SMBUtil.writeInt2(charge, reply, 6);
            SMBUtil.writeInt2(8, reply, 12); // READ
            SMBUtil.writeInt2(this.grant < 0 ? charge : this.grant, reply, 14);
            SMBUtil.writeInt4(1, reply, 16); // server-to-client
            SMBUtil.writeInt8(read.getMid(), reply, 24);
            SMBUtil.writeInt2(17, reply, 64);
            reply[66] = 80;
            SMBUtil.writeInt4(count, reply, 68);
            for ( int i = 0; i < count; i++ ) {
                reply[80 + i] = content(offset + i);
            }
            Smb2ReadResponse response = read.getResponse();
            response.decode(reply, 0);
            response.received();
        }

        Smb2ReadRequest request ( int length ) {
            Smb2ReadRequest request = new Smb2ReadRequest(this.config, new byte[16], new byte[length], 0);
            request.setReadLength(length);
            request.setAllowCreditAdjustment(true);
            return request;
        }

        Smb2ReadResponse read ( Smb2ReadRequest request ) throws IOException {
            return sendrecv(request, null, Collections.<RequestParam>emptySet());
        }

        SmbFile file () throws Exception {
            final SmbTreeHandleImpl tree = mock(SmbTreeHandleImpl.class);
            when(tree.isSMB2()).thenReturn(true);
            when(tree.getConfig()).thenReturn(this.config);
            when(tree.getReceiveBufferSize()).thenReturn(MIB);
            final SmbFileHandleImpl handle = mock(SmbFileHandleImpl.class);
            when(handle.isValid()).thenReturn(true);
            when(handle.acquire()).thenReturn(handle);
            when(handle.getTree()).thenReturn(tree);
            when(handle.getFileId()).thenReturn(new byte[16]);
            when(tree.send(any(Smb2ReadRequest.class), any(RequestParam.class))).thenAnswer(new Answer<Smb2ReadResponse>() {
                @Override
                public Smb2ReadResponse answer ( InvocationOnMock call ) throws Throwable {
                    return read((Smb2ReadRequest) call.getArguments()[0]);
                }
            });
            SmbFile file = mock(SmbFile.class);
            when(file.getType()).thenReturn(SmbConstants.TYPE_FILESYSTEM);
            when(file.ensureTreeConnected()).thenReturn(tree);
            when(file.openUnshared(anyInt(), anyInt(), anyInt(), anyInt(), anyInt())).thenReturn(handle);
            return file;
        }
    }

    @Test
    public void lengthsChargesAndMessageIdsFollowAvailableCredits () throws Exception {
        for ( int credits : new int[] { 1, 2, 8, 16, 32 } ) {
            try ( Peer peer = new Peer(credits) ) {
                Smb2ReadRequest first = peer.request(MIB);
                int expected = Math.min(16, credits);
                assertEquals(expected * CREDIT, peer.read(first).getDataLength());
                Smb2ReadRequest next = peer.request(MIB);
                peer.read(next);
                assertEquals(first.getMid() + expected, next.getMid());
                assertEquals(credits, peer.permits.availablePermits());
            }
        }
    }

    @Test
    public void respectsRequestedLengthAndChangingServerGrants () throws Exception {
        try ( Peer peer = new Peer(16) ) {
            peer.grant = 2;
            assertEquals(MIB, peer.read(peer.request(MIB)).getDataLength());
            peer.grant = 8;
            assertEquals(2 * CREDIT, peer.read(peer.request(MIB)).getDataLength());
            peer.grant = 16;
            assertEquals(8 * CREDIT, peer.read(peer.request(MIB)).getDataLength());
            peer.grant = -1;
            assertEquals(MIB, peer.read(peer.request(MIB)).getDataLength());
            assertEquals(CREDIT + 17, peer.read(peer.request(CREDIT + 17)).getDataLength());
            peer.grant = 0;
            peer.read(peer.request(MIB));
            assertEquals(0, peer.permits.availablePermits());
        }
    }

    @Test(timeout = 5000)
    public void zeroCreditsTimesOutWithoutSendingOrInventingCredits () throws Exception {
        try ( Peer peer = new Peer(0) ) {
            when(peer.config.getResponseTimeout()).thenReturn(30);
            try {
                peer.read(peer.request(MIB));
                fail("Expected credit timeout");
            }
            catch ( SmbException expected ) {
                assertTrue(expected.getMessage().contains("credits"));
            }
            assertTrue(peer.ids.isEmpty());
            assertEquals(0, peer.permits.availablePermits());
        }
    }

    @Test
    public void interruptedCreditWaitKeepsTransportAndInterruptFlag () throws Exception {
        try ( Peer peer = new Peer(0) ) {
            Thread.currentThread().interrupt();
            try {
                peer.read(peer.request(MIB));
                fail("Expected interruption");
            }
            catch ( InterruptedIOException expected ) {
                assertTrue(Thread.currentThread().isInterrupted());
            }
            finally {
                Thread.interrupted();
            }
            assertTrue(peer.ids.isEmpty());
            assertEquals(0, peer.permits.availablePermits());
            peer.permits.release();
            assertEquals(CREDIT, peer.read(peer.request(MIB)).getDataLength());
        }
    }

    @Test(timeout = 10000)
    public void concurrentReadersWaitForOneCreditAndDoNotOverbook () throws Exception {
        final Peer peer = new Peer(1);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        peer.entered = new CountDownLatch(1);
        peer.respond = new CountDownLatch(1);
        when(peer.config.getResponseTimeout()).thenReturn(5000);
        List<Future<Integer>> readers = new ArrayList<Future<Integer>>();
        try {
            for ( int i = 0; i < 4; i++ ) {
                readers.add(executor.submit(new Callable<Integer>() {
                    @Override
                    public Integer call () throws Exception {
                        int total = 0;
                        for ( int j = 0; j < 10; j++ ) {
                            total += peer.read(peer.request(MIB)).getDataLength();
                        }
                        return total;
                    }
                }));
            }
            assertTrue(peer.entered.await(2, TimeUnit.SECONDS));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while ( peer.permits.getQueueLength() < 3 && System.nanoTime() < deadline ) {
                Thread.yield();
            }
            assertEquals("Other readers must wait without a reservation", 3, peer.permits.getQueueLength());
            assertEquals(1, peer.ids.size());
            assertEquals(0, peer.permits.availablePermits());
            peer.respond.countDown();
            for ( Future<Integer> reader : readers ) {
                assertEquals(10 * CREDIT, reader.get(5, TimeUnit.SECONDS).intValue());
            }
            assertEquals(1, peer.permits.availablePermits());
            assertEquals(40, peer.ids.size());
        }
        finally {
            peer.respond.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            peer.release();
        }
    }

    @Test
    public void specialReadsKeepTheirOriginalCreditRequirement () throws Exception {
        try ( Peer peer = new Peer(1) ) {
            when(peer.config.getResponseTimeout()).thenReturn(10);
            for ( int mode = 0; mode < 3; mode++ ) {
                Smb2ReadRequest request = peer.request(MIB);
                if ( mode == 0 ) request.setAllowCreditAdjustment(false);
                if ( mode == 1 ) request.setMinimumCount(MIB);
                if ( mode == 2 ) request.setReadFlags(Smb2ReadRequest.SMB2_READFLAG_READ_UNBUFFERED);
                try {
                    peer.read(request);
                    fail("Special read must retain its original length");
                }
                catch ( SmbException expected ) {
                    assertTrue(expected.getMessage().contains("credits"));
                }
                assertEquals(16, request.getCreditCost());
                assertEquals(1, peer.permits.availablePermits());
                assertTrue(peer.ids.isEmpty());
            }
        }
    }

    @Test(timeout = 10000)
    public void noTimeoutReadResumesWhenOneCreditArrives () throws Exception {
        final Peer peer = new Peer(0);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Integer> reader = executor.submit(new Callable<Integer>() {
                @Override
                public Integer call () throws Exception {
                    Smb2ReadRequest request = peer.request(MIB);
                    Smb2ReadResponse response = peer.sendrecv(request, null, Collections.singleton(RequestParam.NO_TIMEOUT));
                    return response.getDataLength();
                }
            });
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while ( !peer.permits.hasQueuedThreads() && System.nanoTime() < deadline ) {
                Thread.yield();
            }
            assertTrue(peer.permits.hasQueuedThreads());
            assertFalse(reader.isDone());
            peer.permits.release(); // A grant from another in-flight request.
            assertEquals(CREDIT, reader.get(2, TimeUnit.SECONDS).intValue());
            assertEquals(1, peer.permits.availablePermits());
        }
        finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
            peer.release();
        }
    }

    private static byte[] expectedDigest ( long size ) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for ( long i = 0; i < size; i++ ) {
            digest.update(content(i));
        }
        return digest.digest();
    }

    @Test
    public void streamShortReadsPreserveContentAndEof () throws Exception {
        for ( int credits : new int[] { 1, 2, 8, 16 } ) {
            try ( Peer peer = new Peer(credits); SmbFileInputStream stream = new SmbFileInputStream(peer.file()) ) {
                MessageDigest actual = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[MIB + 23];
                int count;
                long total = 0;
                while ( ( count = stream.read(buffer, 23, MIB) ) != -1 ) {
                    assertTrue(count > 0);
                    actual.update(buffer, 23, count);
                    total += count;
                }
                assertEquals(peer.fileSize, total);
                assertArrayEquals(expectedDigest(peer.fileSize), actual.digest());
                assertEquals(-1, stream.read(buffer));
                assertEquals(credits, peer.permits.availablePermits());
            }
        }
    }

    @Test
    public void randomAccessShortReadsPreserveContentAndSeek () throws Exception {
        try ( Peer peer = new Peer(2); SmbRandomAccessFile file = new SmbRandomAccessFile(peer.file(), "r") ) {
            byte[] buffer = new byte[MIB + 23];
            MessageDigest actual = MessageDigest.getInstance("SHA-256");
            int count;
            long total = 0;
            while ( ( count = file.read(buffer, 23, MIB) ) != -1 ) {
                assertTrue(count > 0);
                actual.update(buffer, 23, count);
                total += count;
                assertEquals(total, file.getFilePointer());
            }
            assertEquals(peer.fileSize, total);
            assertArrayEquals(expectedDigest(peer.fileSize), actual.digest());
            file.seek(MIB + 19);
            assertEquals(211, file.read(buffer, 23, 211));
            for ( int i = 0; i < 211; i++ ) {
                assertEquals(content(MIB + 19 + i), buffer[23 + i]);
            }
            assertEquals(MIB + 230, file.getFilePointer());
        }
    }
}

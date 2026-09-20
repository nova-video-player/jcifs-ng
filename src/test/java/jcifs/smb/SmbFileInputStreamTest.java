/*
 * Copyright (C) 2026
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package jcifs.smb;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.smb2.create.Smb2CloseRequest;
import jcifs.internal.smb2.create.Smb2CloseResponse;
import jcifs.internal.smb2.io.Smb2ReadRequest;
import jcifs.internal.smb2.io.Smb2ReadResponse;

/** Tests the real stream/handle against a deterministic in-memory SMB READ responder. */
public class SmbFileInputStreamTest {
    private static final int BLOCK = 8;

    private static Object field ( Object target, String name ) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void await ( CountDownLatch latch ) throws InterruptedException {
        assertTrue("Timed out waiting for worker", latch.await(5, TimeUnit.SECONDS));
    }

    private static class Source implements AutoCloseable {
        volatile byte[] data;
        volatile int maxResponse = BLOCK;
        volatile long blockedOffset = -1;
        volatile boolean failRead;
        volatile int lastRequestLength;
        volatile boolean closeInterrupted;
        final AtomicInteger closes = new AtomicInteger();
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch unblock = new CountDownLatch(1);
        final AtomicInteger reads = new AtomicInteger();
        final SmbFileHandleImpl handle;
        final SmbFileInputStream stream;

        Source ( int length ) throws Exception {
            this(length, BLOCK);
        }

        Source ( int length, int blockSize ) throws Exception {
            this.data = bytes(length);
            this.maxResponse = blockSize;
            Configuration config = mock(Configuration.class);
            SmbTreeHandleImpl tree = mock(SmbTreeHandleImpl.class);
            when(tree.acquire()).thenReturn(tree);
            when(tree.isSMB2()).thenReturn(true);
            when(tree.isConnected()).thenReturn(true);
            when(tree.getReceiveBufferSize()).thenReturn(blockSize);
            when(tree.getConfig()).thenReturn(config);
            SmbFile file = mock(SmbFile.class);
            when(file.getType()).thenReturn(SmbConstants.TYPE_FILESYSTEM);
            this.handle = new SmbFileHandleImpl(config, new byte[16], tree, "test", 0, 0, 0, 0, length);
            this.stream = new SmbFileInputStream(file, tree, this.handle);
            when(tree.send(isA(Smb2CloseRequest.class), eq(RequestParam.NO_RETRY))).thenAnswer(new Answer<Smb2CloseResponse>() {
                @Override
                public Smb2CloseResponse answer ( InvocationOnMock invocation ) {
                    closes.incrementAndGet();
                    closeInterrupted = Thread.currentThread().isInterrupted();
                    return null;
                }
            });
            when(tree.send(isA(Smb2ReadRequest.class), eq(RequestParam.NO_RETRY))).thenAnswer(new Answer<Smb2ReadResponse>() {
                @Override
                public Smb2ReadResponse answer ( InvocationOnMock invocation ) throws Throwable {
                    Smb2ReadRequest request = (Smb2ReadRequest) invocation.getArguments()[0];
                    long offset = (Long) field(request, "offset");
                    int length = (Integer) field(request, "readLength");
                    reads.incrementAndGet();
                    lastRequestLength = length;
                    if ( offset == blockedOffset ) {
                        entered.countDown();
                        await(unblock);
                    }
                    if ( failRead ) {
                        throw new SmbException("Read failed");
                    }
                    byte[] current = data;
                    int n = (int) Math.min(Math.min(length, maxResponse), Math.max(0L, current.length - offset));
                    if ( n > 0 ) {
                        System.arraycopy(current, (int) offset, (byte[]) field(request, "outputBuffer"), 0, n);
                    }
                    Smb2ReadResponse response = mock(Smb2ReadResponse.class);
                    when(response.getDataLength()).thenReturn(n);
                    return response;
                }
            });
        }

        @Override
        public void close () throws Exception {
            this.unblock.countDown();
            Future<?> pending = (Future<?>) field(this.stream, "raPending");
            try {
                if ( pending != null ) {
                    pending.get(5, TimeUnit.SECONDS);
                }
            }
            finally {
                this.stream.close();
            }
        }
    }

    private static byte[] bytes ( int length ) {
        byte[] data = new byte[length];
        for ( int i = 0; i < length; i++ ) {
            data[i] = (byte) (i * 37 + 11);
        }
        return data;
    }

    @Test
    public void sequentialReadsPreserveContents () throws Exception {
        for ( int length : new int[] { 0, 3, 8, 16, 29 } ) {
            for ( int size : new int[] { 1, 3, 8, 19 } ) {
                try ( Source source = new Source(length) ) {
                    ByteArrayOutputStream output = new ByteArrayOutputStream();
                    byte[] buffer = new byte[size + 2];
                    int n;
                    while ( (n = source.stream.read(buffer, 1, size)) != -1 ) {
                        assertTrue("Nonempty read must make progress", n > 0);
                        output.write(buffer, 1, n);
                    }
                    assertArrayEquals(source.data, output.toByteArray());
                    assertEquals(0, source.stream.read(buffer, 0, 0));
                }
            }
        }
    }

    @Test
    public void skipExactBoundaryPreservesNextByte () throws Exception {
        try ( Source source = new Source(24) ) {
            assertEquals(source.data[0] & 0xff, source.stream.read());
            assertEquals(7, source.stream.skip(7));
            assertEquals(source.data[8] & 0xff, source.stream.read());
        }
    }

    @Test
    public void skipWithinAndBeyondBuffer () throws Exception {
        try ( Source source = new Source(32) ) {
            source.stream.read();
            assertEquals(2, source.stream.skip(2));
            assertEquals(source.data[3] & 0xff, source.stream.read());
            assertEquals(17, source.stream.skip(17));
            assertEquals(source.data[21] & 0xff, source.stream.read());
        }
    }

    @Test
    public void shortResponseDoesNotTruncateFile () throws Exception {
        try ( Source source = new Source(19) ) {
            source.maxResponse = 3;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[12];
            int n;
            while ( (n = source.stream.read(buffer)) != -1 ) {
                assertTrue(n > 0);
                output.write(buffer, 0, n);
            }
            assertArrayEquals(source.data, output.toByteArray());
        }
    }

    @Test
    public void smallFileUsesSmallBufferWithoutPrefetch () throws Exception {
        try ( Source source = new Source(3) ) {
            source.stream.read();
            assertEquals(3, ((byte[]) field(source.stream, "raBuf")).length);
            assertNull(field(source.stream, "raPending"));
            assertEquals(1, source.reads.get());
        }
    }

    @Test
    public void smallAndEmptyFilesUseBoundedEofProbes () throws Exception {
        for ( int length : new int[] { 0, 3 } ) {
            try ( Source source = new Source(length, 1024 * 1024) ) {
                byte[] buffer = new byte[1024 * 1024];
                if ( length > 0 ) {
                    assertEquals(length, source.stream.read(buffer));
                    assertEquals(length, source.lastRequestLength);
                }
                assertEquals(-1, source.stream.read(buffer));
                assertTrue("EOF probing must not allocate a negotiated-size buffer", source.lastRequestLength <= 4096);
                assertEquals(-1, source.stream.read());
                assertEquals("Single-byte EOF probe", 1, source.lastRequestLength);
                source.data = bytes(16384);
                ByteArrayOutputStream tail = new ByteArrayOutputStream();
                int n;
                while ( (n = source.stream.read(buffer)) != -1 ) {
                    assertTrue(n > 0);
                    tail.write(buffer, 0, n);
                }
                assertArrayEquals(Arrays.copyOfRange(source.data, length, source.data.length), tail.toByteArray());
            }
        }
    }

    @Test
    public void appendAfterEofIsVisible () throws Exception {
        try ( Source source = new Source(3) ) {
            assertEquals(3, source.stream.read(new byte[8]));
            assertEquals(-1, source.stream.read());
            source.data = bytes(6);
            byte[] tail = new byte[8];
            assertEquals(3, source.stream.read(tail));
            assertArrayEquals(Arrays.copyOfRange(source.data, 3, 6), Arrays.copyOf(tail, 3));
        }
    }

    @Test
    public void interruptedWaitKeepsPendingRequest () throws Exception {
        try ( Source source = new Source(24) ) {
            source.blockedOffset = BLOCK;
            assertEquals(BLOCK, source.stream.read(new byte[BLOCK]));
            await(source.entered);
            Object pending = field(source.stream, "raPending");
            Thread.currentThread().interrupt();
            try {
                source.stream.read();
                fail("Expected interruption");
            }
            catch ( InterruptedIOException expected ) {
                assertTrue(Thread.currentThread().isInterrupted());
                assertSame(pending, field(source.stream, "raPending"));
            }
            finally {
                Thread.interrupted();
                source.unblock.countDown();
            }
            assertEquals(source.data[BLOCK] & 0xff, source.stream.read());
        }
    }

    private static <T> FutureTask<T> start ( Callable<T> task ) {
        FutureTask<T> future = new FutureTask<>(task);
        Thread thread = new Thread(future);
        thread.setDaemon(true);
        thread.start();
        return future;
    }

    @Test
    public void closeWaitsForPrefetchAndReleasesRemoteHandle () throws Exception {
        for ( final boolean interrupt : new boolean[] { false, true } ) {
            try ( final Source source = new Source(24) ) {
                source.blockedOffset = BLOCK;
                source.stream.read(new byte[BLOCK]);
                await(source.entered);
                final CountDownLatch closing = new CountDownLatch(1);
                FutureTask<Boolean> close = start(new Callable<Boolean>() {
                    @Override
                    public Boolean call () throws Exception {
                        if ( interrupt ) {
                            Thread.currentThread().interrupt();
                        }
                        closing.countDown();
                        source.stream.close();
                        return Thread.currentThread().isInterrupted();
                    }
                });
                try {
                    await(closing);
                    try {
                        close.get(100, TimeUnit.MILLISECONDS);
                        fail("Close must not return with an outstanding remote open");
                    }
                    catch ( TimeoutException expected ) {}
                }
                finally {
                    source.unblock.countDown();
                    assertEquals(interrupt, close.get(5, TimeUnit.SECONDS));
                }
                assertFalse(source.handle.isValid());
                assertEquals(1, source.closes.get());
                assertFalse("Cleanup must send CLOSE before restoring interruption", source.closeInterrupted);
                assertEquals(0L, ((java.util.concurrent.atomic.AtomicLong) field(source.handle, "usageCount")).get());
                source.stream.close();
                assertEquals("Repeated close must not release the handle twice", 1, source.closes.get());
                try {
                    source.stream.open();
                    fail("Closed stream must not reopen");
                }
                catch ( SmbException expected ) {}
            }
        }
    }

    @Test
    public void failedPrefetchDoesNotPreventClose () throws Exception {
        try ( Source source = new Source(24) ) {
            source.blockedOffset = BLOCK;
            source.stream.read(new byte[BLOCK]);
            await(source.entered);
            source.failRead = true;
            source.unblock.countDown();
            source.stream.close();
            assertFalse(source.handle.isValid());
            assertEquals(1, source.closes.get());
            assertEquals(0L, ((java.util.concurrent.atomic.AtomicLong) field(source.handle, "usageCount")).get());
        }
    }

    @Test
    public void interruptedSkipPreservesPositionBufferAndPendingRead () throws Exception {
        for ( final int consumed : new int[] { 1, BLOCK } ) {
            try ( final Source source = new Source(32) ) {
                source.blockedOffset = BLOCK;
                source.stream.read(new byte[consumed]);
                await(source.entered);
                Object pending = field(source.stream, "raPending");
                Object buffer = field(source.stream, "raBuf");
                FutureTask<Boolean> skip = start(new Callable<Boolean>() {
                    @Override
                    public Boolean call () throws Exception {
                        Thread.currentThread().interrupt();
                        try {
                            source.stream.skip(2 * BLOCK);
                            fail("Expected interruption");
                            return false;
                        }
                        catch ( InterruptedIOException expected ) {
                            return Thread.currentThread().isInterrupted();
                        }
                    }
                });
                try {
                    assertTrue("Skip must exit while the prefetch is still blocked", skip.get(1, TimeUnit.SECONDS));
                    assertEquals((long) consumed, field(source.stream, "fp"));
                    assertSame(pending, field(source.stream, "raPending"));
                    assertSame(buffer, field(source.stream, "raBuf"));
                }
                finally {
                    source.unblock.countDown();
                }
                assertEquals(source.data[consumed] & 0xff, source.stream.read());
                assertEquals(2 * BLOCK, source.stream.skip(2 * BLOCK));
                assertEquals(source.data[consumed + 1 + 2 * BLOCK] & 0xff, source.stream.read());
            }
        }
    }

    @Test
    public void prefetchFailureIsReportedAndCanBeRetried () throws Exception {
        try ( Source source = new Source(16) ) {
            source.blockedOffset = BLOCK;
            source.stream.read(new byte[BLOCK]);
            await(source.entered);
            source.failRead = true;
            source.unblock.countDown();
            try {
                source.stream.read();
                fail("Expected failed read");
            }
            catch ( IOException expected ) {
                assertEquals("Read failed", expected.getMessage());
            }
            source.failRead = false;
            assertEquals(source.data[BLOCK] & 0xff, source.stream.read());
        }
    }

    @Test
    public void saturatedPoolFallsBackWithoutLeakingHandle () throws Exception {
        java.util.List<Source> busy = new java.util.ArrayList<>();
        try {
            Field poolField = SmbFileInputStream.class.getDeclaredField("READ_AHEAD");
            poolField.setAccessible(true);
            java.util.concurrent.ThreadPoolExecutor pool = (java.util.concurrent.ThreadPoolExecutor) poolField.get(null);
            for ( int i = 0; i < pool.getMaximumPoolSize(); i++ ) {
                Source source = new Source(16);
                busy.add(source);
                source.blockedOffset = BLOCK;
                source.stream.read(new byte[BLOCK]);
                await(source.entered);
            }
            try ( Source source = new Source(24) ) {
                byte[] buffer = new byte[BLOCK];
                assertEquals(BLOCK, source.stream.read(buffer));
                assertNull(field(source.stream, "raPending"));
                assertEquals(1L, ((java.util.concurrent.atomic.AtomicLong) field(source.handle, "usageCount")).get());
                assertEquals(BLOCK, source.stream.read(buffer));
                assertArrayEquals(Arrays.copyOfRange(source.data, BLOCK, 2 * BLOCK), buffer);
            }
        }
        finally {
            for ( Source source : busy ) {
                source.unblock.countDown();
            }
            for ( Source source : busy ) {
                source.close();
            }
        }
    }
}

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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.lang.reflect.Field;

import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.SmbNegotiationResponse;
import jcifs.internal.smb2.Smb2EchoResponse;
import jcifs.util.Encdec;

/** Exercise receive framing with late replies and fragmented socket input. */
public class SmbTransportFramingTest {

    private static byte[] frame ( int size, long mid, boolean smb2 ) {
        byte[] frame = new byte[size + 4];
        Encdec.enc_uint32be(size, frame, 0);
        frame[4] = (byte) ( smb2 ? 0xFE : 0xFF );
        frame[5] = 'S';
        frame[6] = 'M';
        frame[7] = 'B';
        if ( smb2 ) {
            Encdec.enc_uint64le(mid, frame, 28);
        }
        else {
            Encdec.enc_uint16le((short) mid, frame, 34);
        }
        return frame;
    }

    private static SmbTransportImpl transport ( InputStream input, final boolean smb2 ) throws Exception {
        Configuration config = mock(Configuration.class);
        when(config.getReceiveBufferSize()).thenReturn(1024 * 1024);
        when(config.getMaximumBufferSize()).thenReturn(1024 * 1024);
        CIFSContext context = mock(CIFSContext.class);
        when(context.getConfig()).thenReturn(config);
        SmbTransportImpl transport = new SmbTransportImpl(context, null, 445, null, 0, false) {
            @Override
            public boolean isSMB2 () {
                return smb2;
            }
        };
        Field field = SmbTransportImpl.class.getDeclaredField("in");
        field.setAccessible(true);
        field.set(transport, input);
        field = SmbTransportImpl.class.getDeclaredField("negotiated");
        field.setAccessible(true);
        field.set(transport, mock(SmbNegotiationResponse.class));
        return transport;
    }

    private static void assertSkipPreservesNextFrame ( int size, final int skipLimit, boolean smb2 ) throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.write(frame(size, 180, smb2));
        wire.write(frame(80, 185, smb2));
        ByteArrayInputStream input = new ByteArrayInputStream(wire.toByteArray()) {
            @Override
            public synchronized long skip ( long count ) {
                return super.skip(Math.min(count, skipLimit));
            }
        };
        SmbTransportImpl transport = transport(input, smb2);
        try {
            assertEquals(Long.valueOf(180), transport.peekKey());
            transport.doSkip(180L);
            assertEquals("Only the next frame should remain", 84, input.available());
            assertEquals(Long.valueOf(185), transport.peekKey());
        }
        finally {
            transport.release();
        }
    }

    @Test
    public void skipLargeSmb2Replies () throws Exception {
        for ( int size : new int[] { 65536, 65536 + 80, 131072 + 80, 1048576 + 80 } ) {
            assertSkipPreservesNextFrame(size, Integer.MAX_VALUE, true);
        }
    }

    @Test
    public void skipHandlesShortProgress () throws Exception {
        assertSkipPreservesNextFrame(256, 7, true);
    }

    @Test
    public void skipHandlesZeroProgress () throws Exception {
        assertSkipPreservesNextFrame(256, 0, true);
    }

    @Test
    public void skipSmb1Reply () throws Exception {
        assertSkipPreservesNextFrame(256, 7, false);
    }

    @Test(expected = EOFException.class)
    public void truncatedSkippedReplyFails () throws Exception {
        byte[] wire = frame(256, 180, true);
        SmbTransportImpl transport = transport(new ByteArrayInputStream(wire, 0, 100), true);
        try {
            transport.peekKey();
            transport.doSkip(180L);
        }
        finally {
            transport.release();
        }
    }

    @Test
    public void skipUnhandledCompoundTail () throws Exception {
        // Decode a real ECHO response, then discard a response with no caller.
        byte[] compound = frame(72 + 80, 180, true);
        Encdec.enc_uint16le((short) 64, compound, 8);
        Encdec.enc_uint16le((short) 13, compound, 16); // SMB2 ECHO
        Encdec.enc_uint32le(1, compound, 20); // server-to-client response
        Encdec.enc_uint32le(72, compound, 24); // NextCommand
        Encdec.enc_uint16le((short) 4, compound, 68); // ECHO structure size
        System.arraycopy(frame(80, 181, true), 4, compound, 76, 80);
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.write(compound);
        wire.write(frame(80, 185, true));
        ByteArrayInputStream input = new ByteArrayInputStream(wire.toByteArray()) {
            @Override
            public synchronized long skip ( long count ) {
                return super.skip(Math.min(count, 7));
            }
        };
        SmbTransportImpl transport = transport(input, true);
        try {
            assertEquals(Long.valueOf(180), transport.peekKey());
            transport.doRecv(new Smb2EchoResponse(transport.getContext().getConfig()));
            assertEquals("Only the next frame should remain", 84, input.available());
            assertEquals(Long.valueOf(185), transport.peekKey());
        }
        finally {
            transport.release();
        }
    }

    @Test
    public void resynchronizeOnSmb2Header () throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.write(new byte[] { 0x11, 0x22, 0x33 });
        wire.write(frame(80, 185, true));
        ByteArrayInputStream input = new ByteArrayInputStream(wire.toByteArray());
        SmbTransportImpl transport = transport(input, true);
        try {
            assertEquals(Long.valueOf(185), transport.peekKey());
            transport.doSkip(185L);
            assertEquals(0, input.available());
        }
        finally {
            transport.release();
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using TorNet.Interop;

namespace TorNet
{
    internal class SslSocket : Stream
    {
        static SslSocket()
        {
            // Initialize the security interface and retrieve various function pointers
            // from the SSPI initialization result.
            IntPtr functionTable = Secur32.InitSecurityInterface();
            _pfnAcquireCredentialsHandle = Marshal.GetDelegateForFunctionPointer<AcquireCredentialsHandleDelegate>(
                Marshal.ReadIntPtr(functionTable, 3 * IntPtr.Size));
            _pfnApplyControlToken = Marshal.GetDelegateForFunctionPointer<ApplyControlTokenDelegate>(
                Marshal.ReadIntPtr(functionTable, 10 * IntPtr.Size));
            _pfnDecryptMessage = Marshal.GetDelegateForFunctionPointer<DecryptMessageDelegate>(
                Marshal.ReadIntPtr(functionTable, 26 * IntPtr.Size));
            _pfnDeleteSecurityContext = Marshal.GetDelegateForFunctionPointer<DeleteSecurityContextDelegate>(
                Marshal.ReadIntPtr(functionTable, 9 * IntPtr.Size));
            _pfnEncryptMessage = Marshal.GetDelegateForFunctionPointer<EncryptMessageDelegate>(
                Marshal.ReadIntPtr(functionTable, 25 * IntPtr.Size));
            _pfnFreeContextBuffer = Marshal.GetDelegateForFunctionPointer<FreeContextBufferDelegate>(
                Marshal.ReadIntPtr(functionTable, 16 * IntPtr.Size));
            _pfnFreeCredentialsHandle = Marshal.GetDelegateForFunctionPointer<FreeCredentialsHandleDelegate>(
                Marshal.ReadIntPtr(functionTable, 4 * IntPtr.Size));
            _pfnInitializeSecurityContextFirstCall = Marshal.GetDelegateForFunctionPointer<InitializeSecurityContextFirstCallDelegate>(
                Marshal.ReadIntPtr(functionTable, 6 * IntPtr.Size));
            _pfnInitializeSecurityContextContinue = Marshal.GetDelegateForFunctionPointer<InitializeSecurityContextContinuationCallDelegate>(
                Marshal.ReadIntPtr(functionTable, 6 * IntPtr.Size));
            _pfnQueryContextAttributes = Marshal.GetDelegateForFunctionPointer<QueryContextAttributesDelegate>(
                Marshal.ReadIntPtr(functionTable, 11 * IntPtr.Size));
            _pfnQueryCredentialsAttributes = Marshal.GetDelegateForFunctionPointer<QueryCredentialsAttributesDelegate>(
                Marshal.ReadIntPtr(functionTable, 2 * IntPtr.Size));
            return;
        }

        internal SslSocket()
        {
            _hCreds = 0;
            _hContext = 0;
        }

        internal SslSocket(string host, ushort port)
            : this()
        {
            Connect(host, port);
        }

        ~SslSocket()
        {
            TcpSocket socket = UnderlyingSocket;
            if ((null != socket) && (socket.IsConnected)) {
                Close();
            }
            if (0 != _hCreds) {
                _pfnFreeCredentialsHandle(ref _hCreds);
            }
            if (0 != _hContext) {
                _pfnDeleteSecurityContext(ref _hContext);
            }
            if (null != m_pbReceiveBuf) { m_pbReceiveBuf = null; }
            if (null != m_pbIoBuffer) { m_pbIoBuffer= null; }
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            return;
        }

        internal bool IsConnected
        {
            get { return _socket.IsConnected; }
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        internal int Size
        {
            get { throw new NotSupportedException(); }
        }

        internal TcpSocket UnderlyingSocket
        {
            get { return _socket; }
        }

        public override void Close()
        {
            Disconnect(_hCreds, _hContext);
            _socket.Close();
        }

        internal bool Connect(string host, ushort port)
        {
            _socket.Connect(host, port);
            return (_socket.IsConnected && (_handshakeCompleted = ClientConnect(host)));
        }

        /// <summary>This is the very first step. The returned credentials will
        /// be used to create context.</summary>
        /// <param name="hCredentials"></param>
        /// <returns></returns>
        /// <remarks>CONSIDER : customize the channelCredentials structure for fine
        /// tuning of supported protocoles and ciphers.</remarks>
        internal int ClientCreateCredentials(out ulong hCredentials)
        {
            SCHANNEL_CRED channelCredentials = new SCHANNEL_CRED();
            channelCredentials.dwVersion = CredentialsVersion.MostRecentVersion;
            channelCredentials.dwFlags |= CredentialFlags.NoDefaultCredentials
                //| CredentialFlags.NoSystemMapper
                //| CredentialFlags.CheckChainForRevocation;
                | CredentialFlags.ManualCredentialsValidation;

            ulong expirationTimestamp;
            IntPtr nativeChannelCredentials = IntPtr.Zero;
            try {
                nativeChannelCredentials = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(SCHANNEL_CRED)));
                Marshal.StructureToPtr(channelCredentials, nativeChannelCredentials, false);
                return _pfnAcquireCredentialsHandle(null, "Microsoft Unified Security Protocol Provider",
                    CredentialsUseFlags.Outbound, IntPtr.Zero, nativeChannelCredentials,
                    IntPtr.Zero, null, out hCredentials, out expirationTimestamp);
            }
            finally {
                if (IntPtr.Zero != nativeChannelCredentials) {
                    Marshal.FreeCoTaskMem(nativeChannelCredentials);
                }
            }
        }

        internal bool ClientConnect(string host)
        {
            // TODO : pRemoteCertContext is useless in this function.
            if (0 != ClientCreateCredentials(out _hCreds)) {
                return false;
            }
            if (0 != ClientHandshake(host)) {
                return false;
            }
            return true;
        }

        /// <summary>Start establishing the handshake with the server.</summary>
        /// <param name="serverName">Target server name.</param>
        /// <returns></returns>
        private WinErrors ClientHandshake(string serverName)
        {
            _serverName = serverName;

            // First invocation of this function will create the context.
            // TODO : The TargetDataRep parameter from original source code is non zero. This
            // is useless with Schannel
            // TODO : The SECBUFFER_ALERT is missing on input.
            SecurityContextResponseFlags sspiOutputFlags;
            ulong expirationTimestamp;
            IntPtr nativeBuffer = IntPtr.Zero;
            int nativeBufferSize = 0;
            SecBufferDesc outBuffer = new SecBufferDesc(
                new SecBuffer(SecBuffer.Type.SECBUFFER_TOKEN, null),
                new SecBuffer(SecBuffer.Type.SECBUFFER_ALERT, null));
            try {
                nativeBuffer = outBuffer.ToNative(out nativeBufferSize);
                WinErrors scRet = _pfnInitializeSecurityContextFirstCall(ref _hCreds, IntPtr.Zero,
                    _serverName, ContextInitializationInputFlags, 0, 0, IntPtr.Zero, 0, ref _hContext,
                    nativeBuffer, out sspiOutputFlags, out expirationTimestamp);
                if (WinErrors.ContinuationNeeded != scRet) {
                    return scRet;
                }
                outBuffer = SecBufferDesc.FromNative(ref nativeBuffer, nativeBufferSize);
            }
            finally {
                if(IntPtr.Zero != nativeBuffer) {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                }
            }
            if (outBuffer[0].DataLength != 0 && outBuffer[0].pvBuffer != null) {
                _allowPlaintext = true;
                try { Write(outBuffer[0].pvBuffer, outBuffer[0].DataLength); }
                catch {
                    _pfnDeleteSecurityContext(ref _hContext);
                    // return SEC_E_INTERNAL_ERROR;
                    throw;
                }
                _allowPlaintext = false;
            }
            SecBuffer extraData = new SecBuffer();
            WinErrors rc = DoClientHandshakeLoop(true, extraData);
            if (null != extraData.pvBuffer) {
                extraData.pvBuffer = null;
            }
            return rc;
        }

        /// <summary>To be invoked from client side.</summary>
        /// <param name="phCreds"></param>
        /// <param name="phContext"></param>
        /// <returns></returns>
        internal WinErrors Disconnect(ulong /*PCredHandle*/ phCreds,
            ulong /*CtxtHandle*/ phContext)
        {
            int dwType;
            SecurityContextResponseFlags dwSSPIOutFlags;
            ulong tsExpiry;

            dwType = 1; /* SCHANNEL_SHUTDOWN */
            SecBufferDesc outBuffer = new SecBufferDesc(
                new SecBuffer(SecBuffer.Type.SECBUFFER_TOKEN, ((uint)dwType).ToArray()));
            WinErrors nativeStatus = _pfnApplyControlToken(ref phContext, outBuffer);

            if (0 != nativeStatus) {
                return nativeStatus;
            }

            outBuffer = new SecBufferDesc(
                new SecBuffer(SecBuffer.Type.SECBUFFER_TOKEN, null));

            IntPtr nativeOutBuffer = IntPtr.Zero;
            int nativeOutBufferSize = 0;
            try {
                nativeOutBuffer = outBuffer.ToNative(out nativeOutBufferSize);
                nativeStatus = _pfnInitializeSecurityContextContinue(ref phCreds, ref _hContext, null,
                    ContextInitializationInputFlags, 0, DataRepresentation.Native, IntPtr.Zero,
                    0, IntPtr.Zero, nativeOutBuffer, out dwSSPIOutFlags, out tsExpiry);
                outBuffer = SecBufferDesc.FromNative(ref nativeOutBuffer, nativeOutBufferSize);
            }
            finally {
                if (IntPtr.Zero != nativeOutBuffer) {
                    Marshal.FreeCoTaskMem(nativeOutBuffer);
                }
            }
            if (0 != nativeStatus) {
                return nativeStatus;
            }
            byte[] pbMessage = outBuffer[0].pvBuffer;
            int cbMessage = (null == pbMessage) ? 0 : pbMessage.Length;

            if ((null != pbMessage) && (0 != cbMessage)) {
                _allowPlaintext = true;
                _handshakeCompleted = false;
                try { Write(pbMessage, 0, (int)cbMessage); }
                catch {
                    return nativeStatus = WinErrors.InternalError;
                }
                finally { _allowPlaintext = false; }
            }
            _pfnDeleteSecurityContext(ref phContext);
            return nativeStatus;
        }

        private WinErrors DoClientHandshakeLoop(bool doInitialRead, SecBuffer pExtraData)
        {
            int totalIoSize = 0;
            bool doRead = doInitialRead;
            WinErrors lastRetCode = WinErrors.ContinuationNeeded;
            byte[] readBuffer = new byte[IO_BUFFER_SIZE];

            while ((WinErrors.ContinuationNeeded == lastRetCode)
                || (WinErrors.IncompleteMessage == lastRetCode)
                || (WinErrors.IncompleteCredentials == lastRetCode))
            {
                if (   (0 == totalIoSize)
                    || (WinErrors.IncompleteMessage == lastRetCode))
                {
                    if (doRead) {
                        _allowPlaintext = true;
                        int ioSize = Read(readBuffer, readBuffer.Length);
                        if (-1 == ioSize) {
                            lastRetCode = WinErrors.InternalError;
                            break;
                        }
                        if (0 == ioSize) {
                            lastRetCode = WinErrors.InternalError;
                            break;
                        }
                        _allowPlaintext = false;
                        totalIoSize += ioSize;
                    }
                    else {
                        doRead = true;
                    }
                }
                // TODO : In original source code the SECBUFFER_ALERT buffer is missing.
                SecBufferDesc inBuffer = new SecBufferDesc(
                    new SecBuffer(SecBuffer.Type.SECBUFFER_TOKEN, readBuffer, totalIoSize),
                    new SecBuffer(SecBuffer.Type.SECBUFFER_EMPTY));
                SecBufferDesc outBuffer = new SecBufferDesc(
                    new SecBuffer(SecBuffer.Type.SECBUFFER_TOKEN),
                    new SecBuffer(SecBuffer.Type.SECBUFFER_ALERT));

                IntPtr nativeInBuffer = IntPtr.Zero;
                int nativeInBufferSize = 0;
                IntPtr nativeOutBuffer = IntPtr.Zero;
                int nativeOutBufferSize = 0;
                SecurityContextResponseFlags contextAttributes = 0;
                try {
                    nativeInBuffer = inBuffer.ToNative(out nativeInBufferSize);
                    nativeOutBuffer = outBuffer.ToNative(out nativeOutBufferSize);
                    ulong expirationTiestamp;
                    // TODO : Data representation was Native in original source code.
                    lastRetCode = _pfnInitializeSecurityContextContinue(ref _hCreds, ref _hContext,
                        null, ContextInitializationInputFlags, 0, 0, nativeInBuffer, 0, IntPtr.Zero,
                        nativeOutBuffer, out contextAttributes, out expirationTiestamp);
                    outBuffer = SecBufferDesc.FromNative(ref nativeOutBuffer, nativeOutBufferSize);
                }
                finally {
                    if (IntPtr.Zero != nativeInBuffer) {
                        Marshal.FreeCoTaskMem(nativeInBuffer);
                    }
                    if (IntPtr.Zero != nativeOutBuffer) {
                        Marshal.FreeCoTaskMem(nativeOutBuffer);
                    }
                }
                if (   (0 == lastRetCode)
                    || (WinErrors.ContinuationNeeded == lastRetCode)
                    || (   (0 != lastRetCode)
                        && (0 != (contextAttributes & SecurityContextResponseFlags.ExtendedError))))
                {
                    // TODO : Retrieve and validate the returned server context on
                    // on first iteration.
                    if ((null != outBuffer[0].pvBuffer) && (0 != outBuffer[0].DataLength)) {
                        _allowPlaintext = true;
                        try { Write(outBuffer[0].pvBuffer, outBuffer[0].DataLength); }
                        catch {
                            _pfnDeleteSecurityContext(ref _hContext);
                            throw;
                        }
                        finally {
                            _allowPlaintext = false;
                        }
                        // OutBuffer[0].pvBuffer = null;
                    }
                }
                if (WinErrors.IncompleteMessage == lastRetCode) {
                    continue;
                }
                if (lastRetCode == 0) {
                    if (inBuffer[1].BufferType == SecBuffer.Type.SECBUFFER_EXTRA) {
                        pExtraData.pvBuffer = new byte[inBuffer[1].DataLength];
                        if (null == pExtraData.pvBuffer) {
                            return WinErrors.InternalError;
                        }
                        // Note that the extra buffer itself doesn't hold the in excess
                        // data. The only field of interest is the length. So we must 
                        // pick up in excess data from the end of the token buffer we
                        // provided during the last GSS API call.
                        Buffer.BlockCopy(readBuffer /*ioBuffer*/, (int)(totalIoSize - inBuffer[1].DataLength),
                            pExtraData.pvBuffer, 0, (int)inBuffer[1].DataLength);
                        pExtraData.BufferType = SecBuffer.Type.SECBUFFER_TOKEN;
                    }
                    else {
                        pExtraData.pvBuffer = null;
                        pExtraData.BufferType = SecBuffer.Type.SECBUFFER_EMPTY;
                    }
                    break;
                }
                if (WinErrors.UntrustedRoot == lastRetCode) {
                    lastRetCode = 0;
                }
                // if (FAILED(scRet) {
                //   break;
                // }
                if (WinErrors.IncompleteCredentials == lastRetCode) {
                    break;
                }
                if (inBuffer[1].BufferType == SecBuffer.Type.SECBUFFER_EXTRA) {
                    int extraLength = inBuffer[1].DataLength;
                    Buffer.BlockCopy(readBuffer /*ioBuffer*/, (totalIoSize - extraLength),
                        readBuffer /*ioBuffer*/, 0, extraLength);
                    totalIoSize = (int)inBuffer[1].DataLength;
                }
                else {
                    totalIoSize = 0;
                }
            }
            if (0 != lastRetCode) {
                _pfnDeleteSecurityContext(ref _hContext);
            }
            return lastRetCode;
        }

        public int Read(byte[] buffer, int count)
        {
            return Read(buffer, 0, count);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (0 != offset) { throw new ArgumentException(); }
            int rc = 0;
            SecPkgContext_StreamSizes Sizes = new SecPkgContext_StreamSizes();
            uint scRet;
            int cbIoBufferLength;
            int cbData;
            SecBuffer pDataBuffer = new SecBuffer();
            SecBuffer pExtraBuffer = new SecBuffer();
            SecBuffer ExtraBuffer = new SecBuffer();
            byte[] pDataBuf = null;
            uint dwDataLn = 0;
            uint dwBufDataLn = 0;
            bool bCont = true;
            byte[] lpBuf = buffer;
            int nBufLen = count;

            if (_handshakeCompleted) {
                if (0 != m_dwReceiveBuf) {
                    if (nBufLen < m_dwReceiveBuf) {
                        rc = nBufLen;
                        Buffer.BlockCopy(m_pbReceiveBuf, 0, lpBuf, 0, nBufLen);
                        Buffer.BlockCopy(m_pbReceiveBuf, nBufLen, m_pbReceiveBuf, 0,
                            m_dwReceiveBuf - rc);
                        m_dwReceiveBuf -= rc;
                    }
                    else {
                        rc = m_dwReceiveBuf;
                        Buffer.BlockCopy(m_pbReceiveBuf, 0, lpBuf, 0, m_dwReceiveBuf);
                        m_pbReceiveBuf = null;
                        m_dwReceiveBuf = 0;
                    }
                }
                else {
                    do {
                        IntPtr nativeSizes = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(SecPkgContext_StreamSizes)));
                        try {
                            Marshal.StructureToPtr<SecPkgContext_StreamSizes>(Sizes, nativeSizes, false);
                            scRet = (uint)_pfnQueryContextAttributes(ref _hContext,
                                ContextAttributes.SECPKG_ATTR_STREAM_SIZES, nativeSizes);
                        }
                        finally { Marshal.FreeCoTaskMem(nativeSizes); }
                        if (0 != scRet) {
                            throw new ApplicationException();
                        }
                        cbIoBufferLength = (int)(Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer);
                        if (null == m_pbIoBuffer) {
                            m_pbIoBuffer = new byte[cbIoBufferLength];
                        }
                        pDataBuf = new byte[cbIoBufferLength];
                        dwBufDataLn = (uint)cbIoBufferLength;
                        if ((null == m_pbIoBuffer) || (null == pDataBuf)) {
                            break;
                        }
                        do {
                            SecBufferDesc Message = new SecBufferDesc(
                                new SecBuffer(SecBuffer.Type.SECBUFFER_DATA, m_pbIoBuffer),
                                new SecBuffer(SecBuffer.Type.SECBUFFER_EMPTY, null),
                                new SecBuffer(SecBuffer.Type.SECBUFFER_EMPTY, null),
                                new SecBuffer(SecBuffer.Type.SECBUFFER_EMPTY, null));
                            uint trash;
                            scRet = (uint)_pfnDecryptMessage(ref _hContext, ref Message, 0, out trash);
                            if (0x80090318 /* SEC_E_INCOMPLETE_MESSAGE */ == scRet) {
                                cbData = _socket.Read(m_pbIoBuffer, m_cbIoBuffer, (cbIoBufferLength - m_cbIoBuffer));
                                if (-1 == cbData) {
                                    break;
                                }
                                else if (0 == cbData) {
                                    if (0 != m_cbIoBuffer) {
                                        scRet = 0x80090304;
                                    }
                                    break;
                                }
                                else {
                                    m_cbIoBuffer += cbData;
                                }
                                continue;
                            }
                            // TODO : Explain the double test for SEC_I_CONTEXT_EXPIRED
                            // in original source code.
                            if (0x00090317 /*SEC_I_CONTEXT_EXPIRED */ == scRet) {
                                break;
                            }
                            if (0 != scRet
                                && 0x00090321 /* SEC_I_RENEGOTIATE */ != scRet 
                                && 0x00090317 /*SEC_I_CONTEXT_EXPIRED */ != scRet)
                            {
                                break;
                            }
                            bool uninitializedDataBuffer = true;
                            bool uninitializedExtraBuffer = true;
                            for (int i = 1; i < 4; i++) {
                                SecBuffer scannedBuffer = Message[i];
                                SecBuffer.Type scannedBufferType = scannedBuffer.BufferType;
                                if (uninitializedDataBuffer
                                    && scannedBufferType == SecBuffer.Type.SECBUFFER_DATA)
                                {
                                    pDataBuffer = scannedBuffer;
                                    uninitializedDataBuffer = false;
                                }
                                if (uninitializedExtraBuffer
                                    && scannedBufferType == SecBuffer.Type.SECBUFFER_EXTRA)
                                {
                                    uninitializedExtraBuffer = false;
                                    pExtraBuffer = scannedBuffer;
                                }
                            }
                            if (!uninitializedDataBuffer) {
                                int dataBufferLength = pDataBuffer.pvBuffer.Length;
                                if ((dwDataLn + dataBufferLength) > dwBufDataLn) {
                                    byte[] bNewDataBuf = new byte[dwBufDataLn + dataBufferLength];
                                    Buffer.BlockCopy(pDataBuf, 0, bNewDataBuf, 0, (int)dwDataLn);
                                    pDataBuf = bNewDataBuf;
                                    dwBufDataLn = (uint)(dwBufDataLn + dataBufferLength);
                                }
                                Buffer.BlockCopy(pDataBuffer.pvBuffer, 0, pDataBuf, (int)dwDataLn,
                                    dataBufferLength);
                                dwDataLn += (uint)dataBufferLength;
                            }
                            if (!uninitializedExtraBuffer) {
                                int extraBufferLength = pExtraBuffer.pvBuffer.Length;
                                Buffer.BlockCopy(pExtraBuffer.pvBuffer, 0, m_pbIoBuffer,
                                    0, extraBufferLength);
                                m_cbIoBuffer = extraBufferLength;
                                continue;
                            }
                            else {
                                m_cbIoBuffer = 0;
                                bCont = false;
                            }
                            if (0x00090321 /* SEC_I_RENEGOTIATE */ == scRet) {
                                scRet = (uint)DoClientHandshakeLoop(false, ExtraBuffer);
                                if (0 != scRet) {
                                    break;
                                }
                                if (null != ExtraBuffer.pvBuffer) {
                                    int extraBufferLength = pExtraBuffer.pvBuffer.Length;
                                    Buffer.BlockCopy(ExtraBuffer.pvBuffer, 0, m_pbIoBuffer, 0,
                                        extraBufferLength);
                                    m_cbIoBuffer = extraBufferLength;
                                }
                                if (null != ExtraBuffer.pvBuffer) {
                                    ExtraBuffer.pvBuffer = null;
                                }
                            }
                        } while (bCont);
                    } while (false);
                    if (0 != dwDataLn) {
                        if (dwDataLn > nBufLen) {
                            m_dwReceiveBuf = (int)(dwDataLn - nBufLen);
                            m_pbReceiveBuf = new byte[m_dwReceiveBuf];
                            Buffer.BlockCopy(pDataBuf, 0, lpBuf, 0, nBufLen);
                            rc = nBufLen;
                            Buffer.BlockCopy(pDataBuf, nBufLen, m_pbReceiveBuf,
                                0, m_dwReceiveBuf);
                        }
                        else {
                            Buffer.BlockCopy(pDataBuf, 0, lpBuf, 0, (int)dwDataLn);
                            rc = (int)dwDataLn;
                        }
                    }
                    if (null != pDataBuf) { pDataBuf = null; }
                }
            }
            else {
                if (_allowPlaintext) {
                    rc = (int)(_socket.Read(lpBuf, 0, (int)nBufLen));
                }
            }
            return rc;
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public void Write(byte[] buffer, int count)
        {
            Write(buffer, 0, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (0 != offset) { throw new ArgumentException(); }
            SecPkgContext_StreamSizes Sizes = new SecPkgContext_StreamSizes();
            int scRet;
            SecBuffer pDataBuffer;
            SecBuffer pExtraBuffer;
            byte[] pbIoBuffer = null;
            byte[] pbTrailer = null;
            int cbIoBufferLength;
            byte[] pbMessage;
            int cbMessage;

            int dwAvaLn = 0;
            int dwDataToSend = 0;
            int dwSendInd = 0;
            int dwCurrLn = 0;
            int dwTotSent = 0;

            byte[] lpBuf = buffer;
            int nBufLen = count;

            if (_handshakeCompleted) {
                IntPtr nativeBuffer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(SecPkgContext_StreamSizes)));
                try {
                    Marshal.StructureToPtr(Sizes, nativeBuffer, false);
                    scRet = _pfnQueryContextAttributes(ref _hContext, ContextAttributes.SECPKG_ATTR_STREAM_SIZES,
                        nativeBuffer);
                    if (0 != scRet) {
                        throw new ApplicationException();
                    }
                    Sizes = Marshal.PtrToStructure<SecPkgContext_StreamSizes>(nativeBuffer);
                }
                finally {
                    Marshal.FreeCoTaskMem(nativeBuffer);
                }
                //cbIoBufferLength = (int)(Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer);
                //pbIoBuffer = new byte[cbIoBufferLength];
                //pbMessage = pbIoBuffer + Sizes.cbHeader;
                //dwAvaLn = (int)Sizes.cbMaximumMessage;
                //dwDataToSend = nBufLen;
                cbIoBufferLength = (int)(Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer);
                pbIoBuffer = new byte[Sizes.cbHeader];
                pbMessage = new byte[Sizes.cbMaximumMessage];
                pbTrailer = new byte[Sizes.cbTrailer];
                dwAvaLn = (int)Sizes.cbMaximumMessage;
                dwDataToSend = nBufLen;
                do {
                    pbMessage.Zeroize();
                    dwCurrLn = nBufLen - dwSendInd > dwAvaLn ? dwAvaLn : (((int)nBufLen) - dwSendInd);
                    Buffer.BlockCopy(lpBuf, dwSendInd, pbMessage, 0, dwCurrLn);
                    dwSendInd += dwCurrLn;
                    dwDataToSend -= dwCurrLn;
                    cbMessage = dwCurrLn;
                    SecBufferDesc Message = new SecBufferDesc(
                        new SecBuffer(SecBuffer.Type.SECBUFFER_STREAM_HEADER, pbIoBuffer),
                        new SecBuffer(SecBuffer.Type.SECBUFFER_DATA, pbMessage),
                        new SecBuffer(SecBuffer.Type.SECBUFFER_STREAM_TRAILER, pbTrailer),
                        new SecBuffer(SecBuffer.Type.SECBUFFER_EMPTY, null));
                    scRet = _pfnEncryptMessage(ref _hContext, 0, ref Message, 0);
                    if (0 != scRet) {
                        throw new ApplicationException();
                    }
                    bool dataBufferIsUninitialized = true;
                    bool extraBufferIsUninitialized = true;
                    //pDataBuffer = IntPtr.Zero;
                    //pExtraBuffer = null;
                    for (int i = 1; i < 4; i++) {
                        if (dataBufferIsUninitialized
                            && Message[i].BufferType == SecBuffer.Type.SECBUFFER_DATA)
                        {
                            pDataBuffer = Message[i];
                            dataBufferIsUninitialized = false;
                        }
                        if (extraBufferIsUninitialized
                            && Message[i].BufferType == SecBuffer.Type.SECBUFFER_EXTRA)
                        {
                            pExtraBuffer = Message[i];
                            extraBufferIsUninitialized = false;
                        }
                    }
                    int totalWriteSize = (int)(Message[0].pvBuffer.Length
                        + Message[1].pvBuffer.Length
                        + Message[2].pvBuffer.Length);
                    _socket.Write(pbIoBuffer, 0, totalWriteSize);
                    dwTotSent += totalWriteSize;
                    //if ((rc == SOCKET_ERROR) && (WSAGetLastError() == WSAEWOULDBLOCK))
                    //{
                    //    rc = nBufLen;
                    //}
                    //else {
                    //    if (rc == SOCKET_ERROR) {
                    //        dwTotSent = rc;
                    //        break;
                    //    }
                    //    else {
                    //        dwTotSent += rc;
                    //    }
                    //}
                } while (0 != dwDataToSend);
                if (null != pbIoBuffer) { pbIoBuffer = null; }
                return;
            }
            if (!_allowPlaintext) {
                return;
            }
            _socket.Write(lpBuf, 0, nBufLen);
            //if ((rc == SOCKET_ERROR) && (GetLastError() == WSAEWOULDBLOCK)) {
            //    rc = nBufLen;
            //}
            dwTotSent = nBufLen;
            return;
        }

        private static readonly SecurityContextRequestFlags ContextInitializationInputFlags =
              SecurityContextRequestFlags.DetectSequence
            | SecurityContextRequestFlags.DetectReplay
            | SecurityContextRequestFlags.Confidentiality
            | SecurityContextRequestFlags.ExtendedError
            | SecurityContextRequestFlags.AllocateMemory
            | SecurityContextRequestFlags.ManualCredentialsValidation
            | SecurityContextRequestFlags.Stream;
        /// <summary>Plaintext transmission is allowed only during the very first steps
        /// of the handshake. This flag tracks this little window.</summary>
        private bool _allowPlaintext;
        /// <summary>true once the client handshake is completed.</summary>
        private bool _handshakeCompleted;
        /// <summary>Actually a structure with two int.</summary>
        private ulong /*CredHandle*/ _hCreds;
        /// <summary>Actually a structure with two int.</summary>
        private ulong /*CtxtHandle*/ _hContext;
        private string _serverName;
        private TcpSocket _socket = new TcpSocket();

        private byte[] m_pbReceiveBuf;
        private int m_dwReceiveBuf;
        private byte[] m_pbIoBuffer;
        private int m_cbIoBuffer;
        private const int IO_BUFFER_SIZE = 0x10000;
        private const int SECBUFFER_VERSION = 0;

        #region GSSAPI functions definitions with associated enumerations and structures
        //internal delegate int GetKeyFunctionDelegate(IntPtr Arg, IntPtr PrincipalId, uint KeyVer,
        //    out IntPtr Key, out int Status);

        // Notice the explictly defined charset on each delegate. This must be inline with
        // the charset defined for the native function Secur32.InitSecurityInterface
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int AcquireCredentialsHandleDelegate(string pszPrincipal,
            string pszPackage, CredentialsUseFlags fCredentialUse, IntPtr /* PLUID */ pvLogonID,
            IntPtr /* SCHANNEL_CRED */ pAuthData, IntPtr pGetKeyFn, byte[] pvGetKeyArgument,
            out ulong phCredential, out ulong ptsExpiry);
        private static AcquireCredentialsHandleDelegate _pfnAcquireCredentialsHandle;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate WinErrors ApplyControlTokenDelegate(ref ulong /* PCtxtHandle */ phContext,
            [In] SecBufferDesc /* PSecBufferDesc */ pInput);
        private static ApplyControlTokenDelegate _pfnApplyControlToken;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DecryptMessageDelegate(ref ulong /* PCtxtHandle */ phContext,
            ref SecBufferDesc pMessage, uint MessageSeqNo, out uint pfQOP);
        private static DecryptMessageDelegate _pfnDecryptMessage;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int DeleteSecurityContextDelegate(ref ulong /* PCtxtHandle */ phContext);
        private static DeleteSecurityContextDelegate _pfnDeleteSecurityContext;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int EncryptMessageDelegate(ref ulong /* PCtxtHandle */ phContext,
            uint fQOP, ref SecBufferDesc pMessage, uint MessageSeqNo);
        private static EncryptMessageDelegate _pfnEncryptMessage;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int FreeContextBufferDelegate(IntPtr pvContextBuffer);
        private static FreeContextBufferDelegate _pfnFreeContextBuffer;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int FreeCredentialsHandleDelegate(ref ulong /* PCredHandle */ phCredential);
        private static FreeCredentialsHandleDelegate _pfnFreeCredentialsHandle;
        // We need two flavors of the InitializeSecurityContext function in order to be
        // able to pass a null pointer for context.
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate WinErrors InitializeSecurityContextFirstCallDelegate(ref ulong /* PCredHandle */ phCredential,
            IntPtr /* PCtxtHandle */ phContext, string pszTargetName, SecurityContextRequestFlags fContextReq,
            uint Reserved1, DataRepresentation TargetDataRep, IntPtr /* SecBufferDesc* */ pInput, uint Reserved2,
            ref ulong /* PCtxtHandle */ phNewContext, IntPtr /* SecBufferDesc */ pOutput,
            out SecurityContextResponseFlags pfContextAttr, out ulong ptsExpiry);
        private static InitializeSecurityContextFirstCallDelegate _pfnInitializeSecurityContextFirstCall;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate WinErrors InitializeSecurityContextContinuationCallDelegate(ref ulong /* PCredHandle */ phCredential,
            ref ulong /* PCtxtHandle */ phContext, string pszTargetName, SecurityContextRequestFlags fContextReq,
            uint Reserved1, DataRepresentation TargetDataRep, IntPtr /* SecBufferDesc* */ pInput, uint Reserved2,
            IntPtr /* PCtxtHandle */ phNewContext, IntPtr /* SecBufferDesc */ pOutput,
            out SecurityContextResponseFlags pfContextAttr, out ulong ptsExpiry);
        private static InitializeSecurityContextContinuationCallDelegate _pfnInitializeSecurityContextContinue;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int QueryContextAttributesDelegate(ref ulong /* PCtxtHandle */ phContext,
            ContextAttributes ulAttribute, IntPtr pBuffer);
        private static QueryContextAttributesDelegate _pfnQueryContextAttributes;
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate int QueryCredentialsAttributesDelegate(ref ulong /* PCredHandle */ phCredential,
            CredentialsAttributes ulAttribute, ref byte[] pBuffer);
        private static QueryCredentialsAttributesDelegate _pfnQueryCredentialsAttributes;

        private enum ContextAttributes
        {
            SECPKG_ATTR_SIZES = 0,
            SECPKG_ATTR_NAMES = 1,
            SECPKG_ATTR_LIFESPAN = 2,
            SECPKG_ATTR_DCE_INFO = 3,
            SECPKG_ATTR_STREAM_SIZES = 4,
            SECPKG_ATTR_KEY_INFO = 5,
            SECPKG_ATTR_AUTHORITY = 6,
            SECPKG_ATTR_PROTO_INFO = 7,
            SECPKG_ATTR_PASSWORD_EXPIRY = 8,
            SECPKG_ATTR_SESSION_KEY = 9,
            SECPKG_ATTR_PACKAGE_INFO = 10,
            SECPKG_ATTR_USER_FLAGS = 11,
            SECPKG_ATTR_NEGOTIATION_INFO = 12,
            SECPKG_ATTR_NATIVE_NAMES = 13,
            SECPKG_ATTR_FLAGS = 14,
            // These attributes exist only in Win XP and greater
            SECPKG_ATTR_USE_VALIDATED = 15,
            SECPKG_ATTR_CREDENTIAL_NAME = 16,
            SECPKG_ATTR_TARGET_INFORMATION = 17,
            SECPKG_ATTR_ACCESS_TOKEN = 18,
            // These attributes exist only in Win2K3 and greater
            SECPKG_ATTR_TARGET = 19,
            SECPKG_ATTR_AUTHENTICATION_ID = 20,
            // These attributes exist only in Win2K3SP1 and greater
            SECPKG_ATTR_LOGOFF_TIME = 21,
            //
            // win7 or greater
            //
            SECPKG_ATTR_NEGO_KEYS = 22,
            SECPKG_ATTR_PROMPTING_NEEDED = 24,
            SECPKG_ATTR_UNIQUE_BINDINGS = 25,
            SECPKG_ATTR_ENDPOINT_BINDINGS = 26,
            SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27,

            SECPKG_ATTR_LAST_CLIENT_TOKEN_STATUS = 30,
            SECPKG_ATTR_NEGO_PKG_INFO = 31, // contains nego info of packages
            SECPKG_ATTR_NEGO_STATUS = 32, // contains the last error
            SECPKG_ATTR_CONTEXT_DELETED = 33, // a context has been deleted

            SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = 128,
        }

        private enum CredentialsAttributes
        {
            SECPKG_CRED_ATTR_NAMES = 1,
            SECPKG_CRED_ATTR_SSI_PROVIDER = 2,
            SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS = 3,
            SECPKG_CRED_ATTR_CERT = 4,
        }

        [Flags()]
        private enum CredentialsUseFlags : uint
        {
            Inbound = 0x00000001,
            Outbound = 0x00000002,
            Both = 0x00000003,
            Default = 0x00000004,
            Reserved = 0xF0000000,
        }

        private enum DataRepresentation : uint
        {
            Native = 0x00000010,
            Network = 0x00000000
        }

        [Flags()]
        private enum SecurityContextRequestFlags : uint
        {
            Delegate = 0x00000001,
            MutualAuthentication = 0x00000002,
            DetectReplay = 0x00000004,
            DetectSequence = 0x00000008,
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            PromptForCredentials = 0x00000040,
            UseSuppliedCredentials = 0x00000080,
            AllocateMemory = 0x00000100,
            UseDceStyle = 0x00000200,
            Datagram = 0x00000400,
            Connection = 0x00000800,
            CallLevel = 0x00001000,
            FragmentSupplied = 0x00002000,
            ExtendedError = 0x00004000,
            Stream = 0x00008000,
            Integrity = 0x00010000,
            Identify = 0x00020000,
            NullSession = 0x00040000,
            ManualCredentialsValidation = 0x00080000,
            Reserved1 = 0x00100000,
            FragmentToFit = 0x00200000,
            // This exists only in Windows Vista and greater
            ForwardCredentials = 0x00400000,
            NoIntegrity = 0x00800000, // honored only by SPNEGO
            UseHttpStyle = 0x01000000,
        }

        /// <summary>These flags are almost the same than <see cref="SecurityContextRequestFlags"/>.
        /// Howebver there is small differences.</summary>
        [Flags()]
        private enum SecurityContextResponseFlags : uint
        {
            Delegate = 0x00000001,
            MutualAuthentication = 0x00000002,
            DetectReplay = 0x00000004,
            DetectSequence = 0x00000008,
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            UsedCollectedCreds = 0x00000040,
            UsedSuppliedCredentials = 0x00000080,
            AllocateMemory = 0x00000100,
            UsedDceStyle = 0x00000200,
            Datagram = 0x00000400,
            Connection = 0x00000800,
            IntermediateReturn = 0x00001000,
            CallLevel = 0x00002000,
            ExtendedError = 0x00004000,
            Stream = 0x00008000,
            Integrity = 0x00010000,
            Identify = 0x00020000,
            NullSession = 0x00040000,
            ManualCredentialsValidation = 0x00080000,
            Reserved1 = 0x00100000,
            FragmentOnly = 0x00200000,
            // This exists only in Windows Vista and greater
            ForwardCredentials = 0x00400000,
            UseHttpStyle = 0x01000000,
            NoAdditionalToken = 0x02000000,
            Reauthentication = 0x04000000,
        }

        [Serializable()]
        private struct SecBuffer
        {
            internal SecBuffer(Type type, byte[] data = null, int size = -1)
            {
                if ((null == data) && (-1 != size)) {
                    throw new ArgumentNullException();
                }
                if (   (-1 > size)
                    || ((null != data) && (data.Length < size)))
                {
                    throw new ArgumentException();
                }
                BufferType = type;
                // cbBuffer = (uint)((null == data) ? 0 : data.Length);
                if (-1 == size) { pvBuffer = data; }
                else {
                    pvBuffer = new byte[size];
                    Buffer.BlockCopy(data, 0, pvBuffer, 0, size);
                }
                _extraDataSize = 0;
            }

            internal int DataLength
            {
                get
                {
                    return (0 != _extraDataSize)
                        ? _extraDataSize
                        : (null == pvBuffer)
                            ? 0
                            : pvBuffer.Length;
                }
            }

            internal static SecBuffer FromNative(IntPtr native, ref uint offset,
                IntPtr upperBound, List<IntPtr> contextBuffers)
            {
                uint bufferSize = NativeMarshaler.ReadUint32(native, ref offset);
                Type bufferType = (Type)NativeMarshaler.ReadUint32(native, ref offset);
                IntPtr nativeData = NativeMarshaler.ReadIntPtr(native, ref offset);
                if (0 == bufferSize) {
                    return new SecBuffer(bufferType, null);
                }
                else {
                    uint extraDataSize;
                    byte[] data;
                    if (Type.SECBUFFER_EXTRA == bufferType) {
                        extraDataSize = bufferSize;
                        data = null;
                    }
                    else {
                        extraDataSize = 0;
                        if (!nativeData.IsInRange(native, upperBound)) {
                            contextBuffers.Add(nativeData);
                        }
                        data = new byte[bufferSize];
                        Marshal.Copy(nativeData, data, 0, (int)bufferSize);
                    }
                    return new SecBuffer(bufferType, data) {
                        _extraDataSize = (int)extraDataSize
                    };
                }
            }

            internal IntPtr ToNative(NativeMarshaler marshaler = null, int chunkId = -1)
            {
                if (null != marshaler) {
                    if (!marshaler.DoesChunckExist(chunkId)) {
                        throw new InvalidOperationException();
                    }
                }
                else { throw new NotImplementedException(); }
                marshaler.Write((null == pvBuffer) ? 0 : pvBuffer.Length, chunkId);
                marshaler.Write((uint)BufferType, chunkId);
                int myChunk = marshaler[this];
                if (NativeMarshaler.NonExistingChunkId == myChunk) {
                    myChunk = marshaler.NewChunk(this);
                }
                if (null == pvBuffer) {
                    marshaler.Write(IntPtr.Zero, chunkId);
                }
                else {
                    marshaler.WriteRelativePointer(marshaler[myChunk], chunkId);
                    marshaler.Write(pvBuffer, myChunk);
                }
                return IntPtr.Zero;
            }

            // internal uint cbBuffer;             // Size of the buffer, in bytes
            internal Type BufferType; // Type of the buffer (below)
            internal byte[] pvBuffer; // Pointer to the buffer
            /// <summary>This is a special field that is intended for exclusive
            /// use when handling extra data buffer.</summary>
            [NonSerialized()]
            private int _extraDataSize;

            [Flags()]
            internal enum Type : uint
            {
                SECBUFFER_EMPTY = 0,   // Undefined, replaced by provider
                SECBUFFER_DATA = 1,   // Packet data
                SECBUFFER_TOKEN = 2,   // Security token
                SECBUFFER_PKG_PARAMS = 3,   // Package specific parameters
                SECBUFFER_MISSING = 4,   // Missing Data indicator
                SECBUFFER_EXTRA = 5,   // Extra data
                SECBUFFER_STREAM_TRAILER = 6,   // Security Trailer
                SECBUFFER_STREAM_HEADER = 7,   // Security Header
                SECBUFFER_NEGOTIATION_INFO = 8,   // Hints from the negotiation pkg
                SECBUFFER_PADDING = 9,   // non-data padding
                SECBUFFER_STREAM = 10,  // whole encrypted message
                SECBUFFER_MECHLIST = 11,
                SECBUFFER_MECHLIST_SIGNATURE = 12,
                SECBUFFER_TARGET = 13,  // obsolete
                SECBUFFER_CHANNEL_BINDINGS = 14,
                SECBUFFER_CHANGE_PASS_RESPONSE = 15,
                SECBUFFER_TARGET_HOST = 16,
                SECBUFFER_ALERT = 17,

                SECBUFFER_ATTRMASK = 0xF0000000,
                SECBUFFER_READONLY = 0x80000000,  // Buffer is read-only, no checksum
                SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000,  // Buffer is read-only, and checksummed
                SECBUFFER_RESERVED = 0x60000000,  // Flags reserved to security system
            }
        }

        [Serializable()]
        private struct SecBufferDesc
        {
            internal SecBufferDesc(params SecBuffer[] buffers)
            {
                if (Helpers.IsNullOrEmpty(buffers)) {
                    throw new ArgumentNullException();
                }
                //cBuffers = (uint)buffers.Length;
                pBuffers = buffers;
                //ulVersion = SECBUFFER_VERSION;
            }

            internal SecBuffer this[int index]
            {
                get { return pBuffers[index]; }
            }

            internal static SecBufferDesc FromNative(ref IntPtr native, int bufferSize)
            {
                uint offset = 0;
                uint version = NativeMarshaler.ReadUint32(native, ref offset);
                if (1 != version) { throw new ApplicationException(); }
                uint buffersCount = NativeMarshaler.ReadUint32(native, ref offset);
                List<SecBuffer> buffers = new List<SecBuffer>();
                IntPtr arrayBase = NativeMarshaler.ReadIntPtr(native, ref offset);
                List<IntPtr> contextBuffers = new List<IntPtr>();
                IntPtr upperBound = native + bufferSize - 1;
                // Reusing the offset variable.
                offset = 0;
                for(uint index = 0; index < buffersCount; index++) {
                    buffers.Add(
                        SecBuffer.FromNative(arrayBase, ref offset, upperBound,
                            contextBuffers));
                }
                foreach(IntPtr buffer in contextBuffers) {
                    Secur32.FreeContextBuffer(buffer);
                }
                Marshal.FreeCoTaskMem(native);
                try { return new SecBufferDesc(buffers.ToArray()); }
                finally { native = IntPtr.Zero; }
            }

            internal IntPtr ToNative(out int nativeSize)
            {
                NativeMarshaler marshaler = new NativeMarshaler();
                IntPtr result;
                int chunkId = marshaler.NewChunk();
                int arrayChunkId = NativeMarshaler.NonExistingChunkId;
                int arrayOffset = -1;
                do {
                    if (NativeMarshaler.NonExistingChunkId != arrayChunkId) {
                        arrayOffset = marshaler[arrayChunkId]; 
                    }
                    marshaler.Write((uint)1, chunkId);
                    marshaler.Write(pBuffers.Length, chunkId);
                    marshaler.WriteRelativePointer(arrayOffset, chunkId);
                    if (NativeMarshaler.NonExistingChunkId == arrayChunkId) {
                        arrayChunkId = marshaler.NewChunk();
                    }
                    for(int index = 0; index < pBuffers.Length; index++) {
                        pBuffers[index].ToNative(marshaler, arrayChunkId);
                    }
                }
                while (IntPtr.Zero == (result = marshaler.Finalize(out nativeSize)));
                return result;
            }

            //internal uint ulVersion; // Version number
            //internal uint cBuffers; // Number of buffers
            internal SecBuffer[] pBuffers; // Pointer to array of buffers
        }

        [Serializable()]
        private struct SecPkgContext_StreamSizes
        {
            internal uint cbHeader;
            internal uint cbTrailer;
            internal uint cbMaximumMessage;
            internal uint cBuffers;
            internal uint cbBlockSize;
        }

        [Serializable()]
        public struct SCHANNEL_CRED
        {
            public CredentialsVersion dwVersion; // always SCHANNEL_CRED_VERSION
            public uint cCreds;
            public IntPtr /* PCCERT_CONTEXT* */ paCred;
            public IntPtr /*HCERTSTORE*/ hRootStore;
            public uint cMappers;
            public IntPtr /* struct _HMAPPER ** */ aphMappers;
            public uint cSupportedAlgs;
            public IntPtr /* ALG_ID* */ palgSupportedAlgs;
            public uint grbitEnabledProtocols;
            public uint dwMinimumCipherStrength;
            public uint dwMaximumCipherStrength;
            public uint dwSessionLifespan;
            public CredentialFlags dwFlags;
            public uint dwCredFormat;
        }

        [Flags()]
        internal enum CredentialFlags : uint
        {
            NoSystemMapper = 0x00000002,
            NoServarNameCheck = 0x00000004,
            ManualCredentialsValidation = 0x00000008,
            NoDefaultCredentials = 0x00000010,
            AutomatisCredentialsValidation = 0x00000020,
            UseDefaultCredentials = 0x00000040,
            DisableReconnections = 0x00000080,

            CheckEndCertificateForRevocation = 0x00000100,
            CheckChainForRevocation = 0x00000200,
            CheckChainButRootForRevocation = 0x00000400,
            CheckIgnoreNoRevocation = 0x00000800,
            IgnoreRevocationWhenOffline = 0x00001000,

            RestrictRoots = 0x00002000,
            CheckRevocationOnlyFromCache = 0x00004000,
            RetrieveUrlsOnlyFromCache = 0x00008000,

            UseMemoryCertificateStore = 0x00010000,
            RetrieveUrlsOnlyFromCacheOnCreate = 0x00020000,

            SendRootCertificate = 0x00040000,
        }

        internal enum CredentialsVersion
        {
            V1 = 0x00000001,
            V2 = 0x00000002,  // for legacy code
            MostRecentLegacyVersion = 0x00000002, // for legacy code
            V3 = 0x00000003,  // for legacy code
            MostRecentVersion = 0x00000004
        }
        #endregion
    }
}

/* ========================================================================
 * Copyright (c) 2005-2018 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

#include <memory.h>
#include <opcua_platformdefs.h>
#include <opcua_statuscodes.h>
#include <opcua_errorhandling.h>
#include <opcua_trace.h>
#include <opcua_p_binary.h>

/*============================================================================
 * OpcUa_Boolean_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Boolean_P_NativeToWire(OpcUa_Boolean_Wire* wire, OpcUa_Boolean* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *wire = *native;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Boolean_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Boolean_P_WireToNative(OpcUa_Boolean_Wire* native, OpcUa_Boolean_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *native = *wire;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_SByte_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_SByte_P_NativeToWire(OpcUa_SByte_Wire* wire, OpcUa_SByte* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *wire = *native;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_SByte_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_SByte_P_WireToNative(OpcUa_SByte* native, OpcUa_SByte_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *native = *wire;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Byte_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Byte_P_NativeToWire(OpcUa_Byte_Wire* wire, OpcUa_Byte* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *wire = *native;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Byte_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Byte_P_WireToNative(OpcUa_Byte* native, OpcUa_Byte_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    *native = *wire;

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int16_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int16_P_NativeToWire(OpcUa_Int16_Wire* wire, OpcUa_Int16* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_Int16));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int16_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int16_P_WireToNative(OpcUa_Int16* native, OpcUa_Int16_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_Int16));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt16_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt16_P_NativeToWire(OpcUa_UInt16_Wire* wire, OpcUa_UInt16* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_UInt16));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt16_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt16_P_WireToNative(OpcUa_UInt16* native, OpcUa_UInt16_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_UInt16));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int32_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int32_P_NativeToWire(OpcUa_Int32_Wire* wire, OpcUa_Int32* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_Int32));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int32_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int32_P_WireToNative(OpcUa_Int32* native, OpcUa_Int32_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_Int32));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt32_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt32_P_NativeToWire(OpcUa_UInt32_Wire* wire, OpcUa_UInt32* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_UInt32));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt32_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt32_P_WireToNative(OpcUa_UInt32* native, OpcUa_UInt32_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_UInt32));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int64_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int64_P_NativeToWire(OpcUa_Int64_Wire* wire, OpcUa_Int64* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_Int64));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Int64_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Int64_P_WireToNative(OpcUa_Int64* native, OpcUa_Int64_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_Int64));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt64_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt64_P_NativeToWire(OpcUa_UInt64_Wire* wire, OpcUa_UInt64* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_UInt64));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_UInt64_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_UInt64_P_WireToNative(OpcUa_UInt64* native, OpcUa_UInt64_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_UInt64));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Float_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Float_P_NativeToWire(OpcUa_Float_Wire* wire, OpcUa_Float* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_Float));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Float_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Float_P_WireToNative(OpcUa_Float* native, OpcUa_Float_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_Float));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Double_P_NativeToWire
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Double_P_NativeToWire(OpcUa_Double_Wire* wire, OpcUa_Double* native)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(wire, native, sizeof(OpcUa_Double));

    return OpcUa_Good;
}

/*============================================================================
 * OpcUa_Double_P_WireToNative
 *===========================================================================*/
OpcUa_StatusCode OpcUa_Double_P_WireToNative(OpcUa_Double* native, OpcUa_Double_Wire* wire)
{
    OpcUa_DeclareErrorTraceModule(OpcUa_Module_BinarySerializer);
    OpcUa_ReturnErrorIfArgumentNull(wire);
    OpcUa_ReturnErrorIfArgumentNull(native);

    OpcUa_SwapBytes(native, wire, sizeof(OpcUa_Double));

    return OpcUa_Good;
}

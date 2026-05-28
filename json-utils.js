import { pjclHex2BitArray } from './pjcl.js';
import { pjclHex2ByteArray } from './pjcl.js';
import { pjclByteArray2Hex } from './pjcl.js';

export const utf8encoder = new TextEncoder();
export const utf8decoder = new TextDecoder();

export function jsonUtilsHex2String_no_spaces(hex) {
    const byteArray = pjclHex2ByteArray(hex);
    const uint8Array =  new Uint8Array(byteArray);
    const string_no_spaces = utf8decoder.decode(uint8Array);
    return string_no_spaces;
}

export function jsonUtilsHex2Object(hex) {
    const string_no_spaces = jsonUtilsHex2String_no_spaces(hex);
    const object = JSON.parse(string_no_spaces);
    return object;
}

export function jsonUtilsObject2String_four_spaces(object) {
    const string_four_spaces = JSON.stringify(object, null, 4);
    return string_four_spaces;
}

export function jsonUtilsHex2String_four_spaces(hex) {
    const object = jsonUtilsHex2Object(hex);
    const string_four_spaces = jsonUtilsObject2String_four_spaces(object);
    return string_four_spaces;
}

export function jsonUtilsObject2Hex(object) {
    const string = JSON.stringify(object);
    const Uint8Array = utf8encoder.encode(string);
    const hex = pjclByteArray2Hex(Uint8Array);
    return hex;
}

export function jsonUtilsObject2BitArray(object) {
    const string = JSON.stringify(object);
    const Uint8Array = utf8encoder.encode(string);
    const hex = pjclByteArray2Hex(Uint8Array);
    const bitArray = pjclHex2BitArray(hex);
    return bitArray;
}
    

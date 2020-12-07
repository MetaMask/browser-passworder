declare module 'browserify-unibabel' {
  export function utf8ToBuffer(input: string): Uint8Array;
  export function bufferToUtf8(input: Uint8Array): string;
  export function bufferToBase64(input: Uint8Array): string;
  export function base64ToBuffer(input: string): Uint8Array;
}
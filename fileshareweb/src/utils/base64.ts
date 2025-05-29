export const base64 = {
  toByteArray: (base64String: string): Uint8Array => {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
  },
  fromByteArray: (bytes: Uint8Array): string => {
    return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
  }
}; 
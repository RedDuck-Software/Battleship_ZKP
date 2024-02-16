
export const base64ToArrayBuffer = (strings: string): Uint8Array => {

  return Uint8Array.from(
    Buffer.from(strings, "hex")
  );

};

export const arrayBufferToBase64 = (arrayBuffer: ArrayBuffer): string => {
  const b = Buffer.from(arrayBuffer);
  return b.toString("base64");
};

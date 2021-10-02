export class SshBufferReader {
    // The length of the packet in bytes, not including 'mac' or the
    // 'packet_length' field itself.
    // uint32    packet_length
    private packet_length: number;
    // Length of 'random padding' (bytes).
    // byte      padding_length
    private padding_length: number;
    // The useful contents of the packet.  If compression has been
    // negotiated, this field is compressed.  Initially, compression
    // MUST be "none".
    // byte[n1]  payload; n1 = packet_length - padding_length - 1
    private payload: Buffer;
    // Arbitrary-length padding, such that the total length of
    // (packet_length || padding_length || payload || random padding)
    // is a multiple of the cipher block size or 8, whichever is
    // larger.  There MUST be at least four bytes of padding.  The
    // padding SHOULD consist of random bytes.  The maximum amount of
    // padding is 255 bytes.
    // byte[n2]  random padding; n2 = padding_length
    private random_padding: Buffer;
    // Message Authentication Code.  If message authentication has
    // been negotiated, this field contains the MAC bytes.  Initially,
    // the MAC algorithm MUST be "none".
    // byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    private mac: Buffer;
    constructor(data: Buffer) {
        let offset : number = 0;
        // console.log("SshBufferReader.ctor");
        this.packet_length = data.readInt32BE(offset);
        // console.log("packet_length: " + this.packet_length);
        // console.log("offset: " + offset);
        offset += 4;
        this.padding_length = data.readInt8(offset);
        // console.log("padding_length: " + this.padding_length);
        // console.log("offset: " + offset);
        offset += 1;
        let lenOfPayload : number = this.packet_length - this.padding_length - 1;
        // console.log("lenOfPayload: " + lenOfPayload);
        this.payload = data.subarray(offset, offset + lenOfPayload);
        offset += lenOfPayload;
        this.random_padding = data.subarray(offset, offset + this.padding_length);
        // console.log("ORIGINAL");
        // for (const pair of data.entries()) {
        //     console.log(pair);
        // }
        // console.log("PAYLOAD");
        // for (const pair of payloadBuffer.entries()) {
        //     console.log(pair);
        // }
        // console.log("RANDOM PADDING");
        // for (const pair of randomPaddingBuffer.entries()) {
        //     console.log(pair);
        // }
    }

    public getPayload() : Buffer {
        return this.payload;
    }
}
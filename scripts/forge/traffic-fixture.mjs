/** Deterministic TEST-NET Ethernet/IPv4/TCP HTTP bytes; no sockets or capture. */
import { Buffer } from "node:buffer";

const checksum = (bytes) => {
  let sum = 0;
  for (let index = 0; index < bytes.length; index += 2)
    sum += (bytes[index] << 8) | (bytes[index + 1] ?? 0);
  while (sum >>> 16) sum = (sum & 65535) + (sum >>> 16);
  return ~sum & 65535;
};
const tcp = (
  source,
  destination,
  sourcePort,
  destinationPort,
  sequence,
  acknowledgement,
  flags,
  payload,
) => {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(sourcePort);
  header.writeUInt16BE(destinationPort, 2);
  header.writeUInt32BE(sequence, 4);
  header.writeUInt32BE(acknowledgement, 8);
  header[12] = 0x50;
  header[13] = flags;
  header.writeUInt16BE(8192, 14);
  const pseudo = Buffer.concat([
    source,
    destination,
    Buffer.from([0, 6, 0, 20 + payload.length]),
  ]);
  header.writeUInt16BE(checksum(Buffer.concat([pseudo, header, payload])), 16);
  return Buffer.concat([header, payload]);
};
const ipv4 = (source, destination, payload, id) => {
  const header = Buffer.alloc(20);
  header[0] = 0x45;
  header.writeUInt16BE(header.length + payload.length, 2);
  header.writeUInt16BE(id, 4);
  header.writeUInt16BE(0x4000, 6);
  header[8] = 64;
  header[9] = 6;
  source.copy(header, 12);
  destination.copy(header, 16);
  header.writeUInt16BE(checksum(header), 10);
  return Buffer.concat([
    Buffer.from("00112233445566778899aabb0800", "hex"),
    header,
    payload,
  ]);
};
export const offlineHttpFixture = () => {
  const client = Buffer.from([192, 0, 2, 10]),
    server = Buffer.from([198, 51, 100, 20]);
  const request = Buffer.from(
    "GET /fixture.txt HTTP/1.1\r\nHost: example.test\r\n\r\n",
  );
  const response = Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
  );
  const frames = [
    ipv4(
      client,
      server,
      tcp(client, server, 49152, 80, 1, 0, 2, Buffer.alloc(0)),
      1,
    ),
    ipv4(
      server,
      client,
      tcp(server, client, 80, 49152, 10, 2, 18, Buffer.alloc(0)),
      2,
    ),
    ipv4(
      client,
      server,
      tcp(client, server, 49152, 80, 2, 11, 16, Buffer.alloc(0)),
      3,
    ),
    ipv4(client, server, tcp(client, server, 49152, 80, 2, 11, 24, request), 4),
    ipv4(
      server,
      client,
      tcp(server, client, 80, 49152, 11, 2 + request.length, 24, response),
      5,
    ),
  ];
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const packets = frames.map((frame, index) => {
    const packet = Buffer.alloc(16);
    packet.writeUInt32LE(1700000001 + index);
    packet.writeUInt32LE(index + 1, 4);
    packet.writeUInt32LE(frame.length, 8);
    packet.writeUInt32LE(frame.length, 12);
    return Buffer.concat([packet, frame]);
  });
  return Buffer.concat([header, ...packets]);
};

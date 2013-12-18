

var tupin = new ByteString("2515224FFFFFFFFF", HEX);
var upin  = new ByteString("26123456FFFFFFFF", HEX);

var tspin = new ByteString("2576224FFFFFFFFF", HEX);
var spin  = new ByteString("26123456FFFFFFFF", HEX);


var card = new Card(_scsh3.reader);
card.reset(Card.RESET_COLD);

var ef = new CardFile(card, ":2F02");
print(ef.readBinary());

var ef = new CardFile(card, ":0013");
var rec = ef.readRecord(17);
rec = new ASN1(0x30, rec).getBytes();
print(new ASN1(rec));

card.sendApdu(0x00, 0x20, 0x00, 0x06);

//card.sendApdu(0x00, 0x24, 0x00, 0x06, tupin.concat(upin), [0x9000]);

var df = new CardFile(card, "#D27600006601");

df.sendApdu(0x00, 0x20, 0x00, 0x81);
//df.sendApdu(0x00, 0x24, 0x00, 0x81, tspin.concat(spin), [0x9000]);

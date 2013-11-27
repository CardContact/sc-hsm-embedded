

var tupin = new ByteString("2599193FFFFFFFFF", HEX);
var upin  = new ByteString("26123456FFFFFFFF", HEX);

var tspin = new ByteString("2568826FFFFFFFFF", HEX);
var spin  = new ByteString("26123456FFFFFFFF", HEX);


var card = new Card(_scsh3.reader);
card.sendApdu(0x00, 0x24, 0x00, 0x06, tupin.concat(upin), [0x9000]);

var df = new CardFile(card, "#D27600006601");

df.sendApdu(0x00, 0x24, 0x00, 0x81, tspin.concat(spin), [0x9000]);

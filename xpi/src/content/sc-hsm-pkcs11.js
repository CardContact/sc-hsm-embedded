
var pkcsLoader = function (e) {
	var P11 = Components.classes["@mozilla.org/security/pkcs11;1"].getService(Components.interfaces.nsIPKCS11);
	P11.addModule("SmartCard-HSM", ["/usr/local/lib/libsc-hsm-pkcs11.so"], 0x1 << 28, 0);
	//P11.addModule("SmartCard-HSM", ["/usr/local/lib/pkcs11-spy.so"], 0x1 << 28, 0);
}
window.addEventListener ("load", pkcsLoader, false);

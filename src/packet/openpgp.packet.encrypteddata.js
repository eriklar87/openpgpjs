// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
// 
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @class
 * @classdesc Implementation of the Symmetrically Encrypted Data Packet (Tag 9)
 * 
 * RFC4880 5.7: The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 */

function openpgp_packet_encrypteddata() {
	this.tagType = 9;
	this.packetLength = null;
	this.encryptedData = null;
	this.decryptedData = null;
	this.partialPackageLength = null;

	/**
	 * parsing function for the packet.
	 * 
	 * @param {string} input payload of a tag 9 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_packet(input, position, len, partialPackageLength) {
		var mypos = position;
		this.packetLength = len;
		// - Encrypted data, the output of the selected symmetric-key cipher
		// operating in OpenPGP's variant of Cipher Feedback (CFB) mode.
		//this.encryptedData = input.substring(position, position + len);
		this.encryptedData = input;
		this.partialPackageLength = partialPackageLength;
		return this;
	}

	var decryptedBytes = 30;
	function getDecryptedBytes() {
		return decryptedBytes;
	}
	/**
	 * symmetrically decrypt the packet data
	 * 
	 * @param {integer} symmetric_algorithm_type
	 *             symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key
	 *             key as string with the corresponding length to the
	 *            algorithm
	 * @return the decrypted data;
	 */
	function decrypt_sym(symmetric_algorithm_type, key, progressCallback) {
		this.decryptedData = openpgp_crypto_symmetricDecrypt(
				symmetric_algorithm_type, key, this.encryptedData, true, this.partialPackageLength, progressCallback);
		
		return this.decryptedData;
	}

	/**
	 * Creates a string representation of the packet
	 * 
	 * @param {Integer} algo symmetric key algorithm to use // See RFC4880 9.2
	 * @param {String} key key as string with the corresponding length to the
	 *            algorithm
	 * @param {String} data data to be
	 * @return {String} string-representation of the packet
	 */
	function write_packet(algo, key, data) {
		var result = "";
		result += openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true);
		result = openpgp_packet.write_packet_header(9, result.length) + result;
		return result;
	}

	function write_packet_large(algo, key, data, progressCallback) {
		var result = openpgp_crypto_symmetricEncrypt(
				openpgp_crypto_getPrefixRandom(algo), algo, key, data, true, "BLOB", progressCallback);
		var header = openpgp_packet.write_packet_header(9, result.size);
		var arrHeader = new Uint8Array(header.length);
		for(var i = 0; i<arrHeader.length; i++)
		{
			arrHeader[i] = header[i].charCodeAt();
		}
		result = new Blob([util.getArrayStoreFormat(arrHeader), result], {type: 'application/octet-stream'});
		return result;
	}
	
	function toString() {
		return '5.7.  Symmetrically Encrypted Data Packet (Tag 9)\n'
				+ '    length:  ' + this.packetLength + '\n'
				+ '    Used symmetric algorithm: ' + this.algorithmType + '\n'
				+ '    encrypted data: Bytes ['
				+ util.hexstrdump(this.encryptedData) + ']\n';
	}
	this.decrypt_sym = decrypt_sym;
	this.toString = toString;
	this.read_packet = read_packet;
	this.write_packet = write_packet;
	this.write_packet_large = write_packet_large;
	this.getDecryptedBytes = getDecryptedBytes;
};

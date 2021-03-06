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
 * @classdesc Public-Key Encrypted Session Key Packets (Tag 1)
 * 
 * RFC4880 5.1: A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 */
function openpgp_packet_encryptedsessionkey() {

	/**
	 * parsing function for a publickey encrypted session key packet (tag 1).
	 * 
	 * @param {string} input payload of a tag 1 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_pub_key_packet(input, position, len) {
		this.tagType = 1;
		this.packetLength = len;
		var mypos = position;
		if (len < 10) {
			util
					.print_error("openpgp.packet.encryptedsessionkey.js\n" + 'invalid length');
			return null;
		}

		this.version = input[mypos++].charCodeAt();
		this.keyId = new openpgp_type_keyid();
		this.keyId.read_packet(input, mypos);
		mypos += 8;
		this.publicKeyAlgorithmUsed = input[mypos++].charCodeAt();

		switch (this.publicKeyAlgorithmUsed) {
		case 1:
		case 2: // RSA
			this.MPIs = new Array();
			this.MPIs[0] = new openpgp_type_mpi();
			this.MPIs[0].read(input, mypos, mypos - position);
			break;
		case 16: // Elgamal
			this.MPIs = new Array();
			this.MPIs[0] = new openpgp_type_mpi();
			this.MPIs[0].read(input, mypos, mypos - position);
			mypos += this.MPIs[0].packetLength;
			this.MPIs[1] = new openpgp_type_mpi();
			this.MPIs[1].read(input, mypos, mypos - position);
			break;
		default:
			util.print_error("openpgp.packet.encryptedsessionkey.js\n"
					+ "unknown public key packet algorithm type "
					+ this.publicKeyAlgorithmType);
			break;
		}
		return this;
	}

	/**
	 * create a string representation of a tag 1 packet
	 * 
	 * @param {String} publicKeyId
	 *             the public key id corresponding to publicMPIs key as string
	 * @param {Array[openpgp_type_mpi]} publicMPIs
	 *            multiprecision integer objects describing the public key
	 * @param {integer} pubalgo
	 *            the corresponding public key algorithm // See RFC4880 9.1
	 * @param {integer} symmalgo
	 *            the symmetric cipher algorithm used to encrypt the data within 
	 *            an encrypteddatapacket or encryptedintegrityprotecteddatapacket 
	 *            following this packet //See RFC4880 9.2
	 * @param {String} sessionkey
	 *            a string of randombytes representing the session key
	 * @return {String} the string representation
	 */
	function write_pub_key_packet(publicKeyId, publicMPIs, pubalgo, symmalgo,
			sessionkey) {
		var result = String.fromCharCode(3);
		var data = String.fromCharCode(symmalgo);
		data += sessionkey;
		var checksum = util.calc_checksum(sessionkey);
		data += String.fromCharCode((checksum >> 8) & 0xFF);
		data += String.fromCharCode((checksum) & 0xFF);
		result += publicKeyId;
		result += String.fromCharCode(pubalgo);
		var mpi = new openpgp_type_mpi();
		var mpiresult = openpgp_crypto_asymetricEncrypt(pubalgo, publicMPIs,
				mpi.create(openpgp_encoding_eme_pkcs1_encode(data,
						publicMPIs[0].mpiByteLength)));
		for ( var i = 0; i < mpiresult.length; i++) {
			result += mpiresult[i];
		}
		result = openpgp_packet.write_packet_header(1, result.length) + result;
		return result;
	}
	
	/**
	 * create a string representation of a tag 3 packet
	 * NOT COMPLETE. THE SESSION KEY SHOULD BE TAKEN AS AN OPTIONAL PARAM AS WELL
	 * 
	 * @param symmalgo
	 *            [integer] the symmetric cipher algorithm used to encrypt the
	 *            data within an encrypteddatapacket or
	 *            encryptedintegrityprotecteddatapacket following this packet //
	 *            See RFC4880 9.2
	 * @param s2kType [number] The String-to-Key type used to derive the key
	 * @param passphrase [String] The pass phrase used by the s2k.
	 * @param hash [number] The hash type to be used by the algorithm.
	 * @param salet [string] The salt for the s2k.
	 * @param c [number] The coded count (see https://tools.ietf.org/html/rfc4880#section-3.7)
	 * @param sessionKey [String] Optional. The encrypted session key.
	 * @return [String] the string representation
	 */
	function write_symmetric_key_packet(symmalgo, s2kType, passphrase, hash, salt, c, sessionKey) {
		var result = String.fromCharCode(4); // Version number, always 4.
		result += String.fromCharCode(symmalgo); // Append sym algo.
		var s2k = new openpgp_type_s2k();
		
		// TODO: Add TrippleDES
		var nbrKeyBytes = 0;
		if(symmalgo == 3 || symmalgo == 4 || symmalgo == 7) 
		{
			nbrKeyBytes = 16;
		} 
		else if(symmalgo == 8) 
		{
			nbrKeyBytes = 24;
		} 
		else if(symmalgo == 9 || symmalgo == 10) 
		{
			nbrKeyBytes = 32;
		}
		
		this.key = s2k.write(s2kType, hash, passphrase, salt, c, nbrKeyBytes);
		result += String.fromCharCode(s2k.type);
		result += String.fromCharCode(s2k.hashAlgorithm);
		result += salt;
		
		this.s2k = s2k;
		
		result += String.fromCharCode(c); // Append s2k-identifier. 
		
		if(sessionKey != undefined) {
			result += sessionKey;
		}
		
		result = openpgp_packet.write_old_packet_header(3, result.length) + result;
		return result;
	}
	

	/**
	 * parsing function for a symmetric encrypted session key packet (tag 3).
	 * 
	 * @param {string} input payload of a tag 1 packet
	 * @param {integer} position position to start reading from the input string
	 * @param {integer} len
	 *            length of the packet or the remaining length of
	 *            input at position
	 * @return {openpgp_packet_encrypteddata} object representation
	 */
	function read_symmetric_key_packet(input, position, len) {
		this.tagType = 3;
		var mypos = position;
		// A one-octet version number. The only currently defined version is 4.
		util.print_debug("Version: " + input.get(mypos));
		this.version = input.get(mypos++);
		//util.print_debug("Version: " + input.get(mypos).charCodeAt());
		//this.version = input.get(mypos++).charCodeAt();

		// A one-octet number describing the symmetric algorithm used.
		//util.print_debug("Symmetric key algo: " + input.get(mypos).charCodeAt());
		//this.symmetricKeyAlgorithmUsed = input.get(mypos++).charCodeAt();
		util.print_debug("Symmetric key algo: " + input.get(mypos));
		this.symmetricKeyAlgorithmUsed = input.get(mypos++);
		
		// A string-to-key (S2K) specifier, length as defined above.
		this.s2k = new openpgp_type_s2k();
		this.s2k.read(input, mypos);

		// Optionally, the encrypted session key itself, which is decrypted
		// with the string-to-key object.
		if ((this.s2k.s2kLength + mypos) < len) {
			this.encryptedSessionKey = new Array();
			for ( var i = (mypos - position); i < len; i++) {
				this.encryptedSessionKey[i] = String.fromCharCode(input.get(mypos++));
				//this.encryptedSessionKey[i] = input.get(mypos++);
			}
		}
		
		return this;
	}
	/**
	 * Decrypts the session key (only for public key encrypted session key
	 * packets (tag 1)
	 * 
	 * @param {openpgp_msg_message} msg
	 *            the message object (with member encryptedData
	 * @param {openpgp_msg_privatekey} key
	 *            private key with secMPIs unlocked
	 * @return {String} the unencrypted session key
	 */
	function decrypt(msg, key) {
		if (this.tagType == 1) {
			var result = openpgp_crypto_asymetricDecrypt(
					this.publicKeyAlgorithmUsed, key.publicKey.MPIs,
					key.secMPIs, this.MPIs).toMPI();
			var checksum = ((result.charCodeAt(result.length - 2) << 8) + result
					.charCodeAt(result.length - 1));
			var decoded = openpgp_encoding_eme_pkcs1_decode(result.substring(2, result.length - 2), key.publicKey.MPIs[0].getByteLength());
			var sesskey = decoded.substring(1);
			var algo = decoded.charCodeAt(0);
			if (msg.encryptedData.tagType == 18)
				return msg.encryptedData.decrypt(algo, sesskey);
			else
				return msg.encryptedData.decrypt_sym(algo, sesskey);
		} else if (this.tagType == 3) {
			util
					.print_error("Symmetric encrypted sessionkey is not supported!");
			return null;
		}
	}

	/**
	 * Creates a string representation of this object (useful for debug
	 * purposes)
	 * 
	 * @return the string containing a openpgp description
	 */
	function toString() {
		if (this.tagType == 1) {
			var result = '5.1.  Public-Key Encrypted Session Key Packets (Tag 1)\n'
					+ '    KeyId:  '
					+ this.keyId.toString()
					+ '\n'
					+ '    length: '
					+ this.packetLength
					+ '\n'
					+ '    version:'
					+ this.version
					+ '\n'
					+ '    pubAlgUs:'
					+ this.publicKeyAlgorithmUsed + '\n';
			for ( var i = 0; i < this.MPIs.length; i++) {
				result += this.MPIs[i].toString();
			}
			return result;
		} else
			return '5.3 Symmetric-Key Encrypted Session Key Packets (Tag 3)\n'
					+ '    length: ' + this.packetLength + '\n'
					+ '    version:' + this.version + '\n' + '    symKeyA:'
					+ this.symmetricKeyAlgorithmUsed + '\n' + '    s2k:    '
					+ this.s2k + '\n';
	}

	this.read_pub_key_packet = read_pub_key_packet;
	this.read_symmetric_key_packet = read_symmetric_key_packet;
	this.write_symmetric_key_packet = write_symmetric_key_packet;
	this.write_pub_key_packet = write_pub_key_packet;
	this.toString = toString;
	this.decrypt = decrypt;
};


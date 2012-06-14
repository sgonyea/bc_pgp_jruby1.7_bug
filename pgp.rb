#!/usr/bin/env jruby

require 'java'
require 'jars/bcprov-jdk16-146.jar'
require 'jars/bcmail-jdk16-146.jar'
require 'jars/bctsp-jdk16-146.jar'
require 'jars/bcpg-jdk16-146.jar'

module PGP
  java_import 'java.io.ByteArrayInputStream'
  java_import 'java.io.ByteArrayOutputStream'
  java_import 'java.io.DataOutputStream'
  java_import 'java.security.NoSuchProviderException'
  java_import 'java.security.SecureRandom'
  java_import 'java.security.Security'
  java_import 'org.bouncycastle.jce.provider.BouncyCastleProvider'
  java_import 'org.bouncycastle.bcpg.ArmoredOutputStream'

  include_package "org.bouncycastle.openpgp"

  Public_Key  = "#{Root_Dir}/keys/bc_pgp_jruby_bug-pub.asc"
  Private_Key = "#{Root_Dir}/keys/bc_pgp_jruby_bug-prv.asc"
  Email_Addr  = "foo@bar.com"

  BC_Provider_Code = "BC"

  Security.add_provider BouncyCastleProvider.new

  # This is so awful. The Bouncy Castle API is trash.
  def self.private_key_for_id(key_id)
    file    = File.open(Private_Key)
    pgp_sec = PGPSecretKeyRingCollection.new(PGPUtil.get_decoder_stream(file.to_inputstream))
    sec_key = pgp_sec.get_secret_key(key_id)

    if sec_key then sec_key.extract_private_key(nil, BC_Provider_Code)
    else
      nil
    end
  end

  def self.public_key_from_filename(filename)
    file    = File.open(filename)
    pk_col  = PGPPublicKeyRingCollection.new(PGPUtil.get_decoder_stream(file.to_inputstream))

    key_enumerator = pk_col.get_key_rings
    encryption_key = nil

    key_enumerator.each do |pk_ring|
      pk_enumerator = pk_ring.get_public_keys

      pk_enumerator.each do |key|
        next unless key.is_encryption_key

        encryption_key = key
        break
      end
    end

    encryption_key
  end

  def self.encrypt_file(filename)
    encrypt(File.read filename)
  end

  # @param [PGPLiteralDataGenerator] pldg
  # @return [Method] The Java Method :open for the given pldg
  def self.pgp_literal_data_generator_to_open_call(pldg)
    pldg.java_method :open, [java.io.OutputStream, Java::char, java.lang.String, Java::long, java.util.Date]
  end

  Public_Keys = {
    :bc_pgp_jruby_bug => public_key_from_filename(Public_Key)
  }

  # This exists for testing porpoises. Stubbing Time.now directly isn't worth the effort.
  def self.modification_time
    Time.now
  end

  def self.pipe_contents(plain_text, p_out)
    bytes = plain_text.to_java_bytes

    p_out.write(bytes, 0, bytes.length)
  end

  def self.encrypt(plain_text, key_name=:bc_pgp_jruby_bug)
    key = Public_Keys[key_name]

    baos  = ByteArrayOutputStream.new

    out   = ArmoredOutputStream.new(baos)
    b_out = ByteArrayOutputStream.new

    com_data = PGPCompressedDataGenerator.new(PGPCompressedDataGenerator::ZIP)

    pldg = PGPLiteralDataGenerator.new
    pldg_open = pgp_literal_data_generator_to_open_call(pldg)

    p_out = pldg_open.call(
      com_data.open(b_out),   # OutputStream  out
      PGPLiteralData::BINARY, # char          format
      "pgp",                  # String        name
      plain_text.length,      # long          length
      modification_time       # Date          modificationTime
    )

    pipe_contents(plain_text, p_out)

    com_data.close

    bytes = b_out.to_byte_array

    cpk = PGPEncryptedDataGenerator.new(PGPEncryptedDataGenerator::CAST5, SecureRandom.new, BC_Provider_Code)
    cpk.add_method(key)

    c_out = cpk.open(out, bytes.length)
    c_out.write(bytes)

    cpk.close
    out.close

    baos.to_string
  end

  def self.decrypt_file(filename)
    file = File.read(filename)
    decrypt(file)
  end

  def self.decrypt(encrypted_text)
    bytes = ByteArrayInputStream.new(encrypted_text.to_java_bytes)
    dec_s = PGPUtil.get_decoder_stream(bytes)
    pgp_f = PGPObjectFactory.new(dec_s)

    enc_data = pgp_f.next_object
    enc_data = pgp_f.next_object unless PGPEncryptedDataList === enc_data

    data_enumerator = enc_data.get_encrypted_data_objects

    sec_key = nil
    pbe     = nil

    data_enumerator.each do |pubkey_enc_data|
      pbe     = pubkey_enc_data
      key_id  = pubkey_enc_data.get_key_id
      sec_key = private_key_for_id(key_id)

      if sec_key.nil?
        # Commented out for this example.
        # logger.debug "This may be cause for concern. The data being decrypted has a key_id of '#{key_id}'."
      else
        break
      end
    end

    clear = pbe.get_data_stream(sec_key, BC_Provider_Code)

    plain_fact = PGPObjectFactory.new(clear)

    message = plain_fact.next_object

    if(PGPCompressedData === message)
      pgp_fact  = PGPObjectFactory.new(message.get_data_stream)
      message   = pgp_fact.next_object
    end

    baos = ByteArrayOutputStream.new

    if(PGPLiteralData === message)
      unc = message.get_input_stream
      while((ch = unc.read) >= 0)
        baos.write(ch)
      end
    end

    baos.to_string
  end

end

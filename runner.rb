#!/usr/bin/env jruby

Root_Dir = File.dirname(File.expand_path(__FILE__))
$LOAD_PATH.unshift(Root_Dir)

require 'pgp'

string  = "8==============D"

puts "This example will encrypt data, and then decrypt that data."
puts "Private Key:  #{PGP::Private_Key}"
puts "Public Key:   #{PGP::Public_Key}"
puts
puts "Encrypting string: #{string.inspect}"
puts "......"

encrypted_data = PGP.encrypt(string)

puts "Encrypted value (ASCII Armored): #{encrypted_data.inspect}"

puts
puts "Decrypting...."

decrypted_data = PGP.decrypt(encrypted_data)

puts "Decrypted value: #{decrypted_data.inspect}"

#!/usr/bin/perl -w

###  EncryptForFun.pl
###  Avi Kak  (kak@purdue.edu)
###  January 11, 2016

###  Medium strength encryption/decryption for secure message exchange
###  for fun.

###  Based on differential XORing of bit blocks.  Differential XORing
###  destroys any repetitive patterns in the messages to be encrypted and
###  makes it more difficult to break encryption by statistical
###  analysis. Differential XORing needs an Initialization Vector that is
###  derived from a pass phrase in the script shown below.  The security
###  level of this script can be taken to full strength by using 3DES or
###  AES for encrypting the bit blocks produced by differential XORing.

###  Call syntax:
###
###       EncryptForFun.pl  message_file.txt  output.txt
###
###  The encrypted output is deposited in the file `output.txt'

use strict;
use Algorithm::BitVector;                                                   #(A)

die "Needs two command-line arguments, one for the name of " .
    "message file and the other for the name to be used for " .
    "encrypted output file"
    unless @ARGV == 2;                                                      #(B) 

my @PassPhrase = split //, "Hopes and dreams of a million years";           #(C)

my $BLOCKSIZE = 64;                                                         #(D)
my $numbytes = int($BLOCKSIZE / 8);                                         #(E)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
my $bv_iv = Algorithm::BitVector->new(bitlist => [(0) x $BLOCKSIZE]); 
                                                                            #(F)
foreach my $i (0 .. int(@PassPhrase / $numbytes) - 1) {                     #(G)
    my $textstr = join '', @PassPhrase[$i*$numbytes .. ($i+1)*$numbytes-1]; #(H)
    $bv_iv ^= Algorithm::BitVector->new(textstring => $textstr);            #(I)
}

# Get key from user:
print "\nEnter key: ";                                                      #(J)
my $key_input = <STDIN>;                                                    #(K)
$key_input =~ s/^\s+|\s$//g;                                                #(L)
my @key = split //, $key_input;                                             #(M)

# Reduce the key to a bit array of size BLOCKSIZE:
my $key_bv = Algorithm::BitVector->new( bitlist => [(0)x$BLOCKSIZE] );      #(N)
foreach my $i (0 .. int(@key / $numbytes) - 1) {                            #(O)
    my $keyblock = join '', @key[ $i*$numbytes .. ($i+1)*$numbytes - 1 ];   #(P)
    $key_bv ^= Algorithm::BitVector->new(textstring => $keyblock);          #(Q)
}

# Create a bitvector for storing the ciphertext bit array:
my $msg_encrypted_bv = Algorithm::BitVector->new( size => 0 );              #(R)

# Carry out differential XORing of bit blocks and encryption:
my $previous_block = $bv_iv;                                                #(S)
my $bv = Algorithm::BitVector->new(filename => shift);                      #(T)
while ($bv->{more_to_read}) {                                               #(U)
    my $bv_read = $bv->read_bits_from_file($BLOCKSIZE);                     #(V)
    if (length($bv_read) < $BLOCKSIZE) {                                    #(W)
        $bv_read += Algorithm::BitVector->new(size => 
                                 ($BLOCKSIZE - length($bv_read)));          #(X)
    }
    $bv_read ^= $key_bv;                                                    #(Y)
    $bv_read ^= $previous_block;                                            #(Z)
    $previous_block = $bv_read->deep_copy();                                #(a)
    $msg_encrypted_bv += $bv_read;                                          #(b)
}

# Convert the encrypted bitvector into a hex string:
my $outputhex = $msg_encrypted_bv->get_hex_string_from_bitvector();         #(c)

# Write ciphertext bitvector to the output file:
open FILEOUT, ">" . shift or die "unable to open file: $!";                 #(d)
print FILEOUT $outputhex;                                                   #(e)
close FILEOUT or die "unable to close file: $!";                            #(f)

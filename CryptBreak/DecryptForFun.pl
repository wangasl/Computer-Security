#!/usr/bin/perl -w

###  DecryptForFun.pl
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
###       DecryptForFun.pl   output.txt   recover.txt
###
###  The decrypted message is deposited in the file `recover.txt'

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
my $bv_iv = Algorithm::BitVector->new(bitlist => [(0) x $BLOCKSIZE]);       #(F)
foreach my $i (0 .. int(@PassPhrase / $numbytes) - 1) {                     #(G)
    my $textstr = join '', @PassPhrase[$i*$numbytes .. ($i+1)*$numbytes-1]; #(H)
    $bv_iv ^= Algorithm::BitVector->new(textstring => $textstr);            #(I)
}

# Create a bitvector from the ciphertext hex string:
open FILEIN, shift or die "unable to open file: $!";                        #(J)
my $encrypted_bv = Algorithm::BitVector->new( hexstring => <FILEIN> );      #(K)

# Get key from user:
print "\nEnter key: ";                                                      #(L)
my $key_input = <STDIN>;                                                    #(M)
$key_input =~ s/^\s+|\s$//g;                                                #(N)
my @key = split //, $key_input;                                             #(O)

# Reduce the key to a bit array of size BLOCKSIZE:
my $key_bv = Algorithm::BitVector->new( bitlist => [(0) x $BLOCKSIZE] );    #(P)
foreach my $i (0 .. int(@key / $numbytes) - 1) {                            #(Q)
    my $keyblock = join '', @key[ $i*$numbytes .. ($i+1) * $numbytes - 1];  #(R)
    $key_bv ^= Algorithm::BitVector->new(textstring => $keyblock);          #(S)
}

# Create a bitvector for storing the decrypted plaintext bit array:
my $msg_decrypted_bv = Algorithm::BitVector->new( size => 0 );              #(T)

# Carry out differential XORing of bit blocks and decryption:
my $previous_decrypted_block = $bv_iv;                                      #(U)
foreach my $i (0 .. int(length($encrypted_bv)/$BLOCKSIZE - 1)) {            #(V)
    my $bv = Algorithm::BitVector->new( bitlist => $encrypted_bv->get_bit( 
                    [$i*$BLOCKSIZE .. ($i+1)*$BLOCKSIZE - 1] ) );           #(W)
    my $temp = $bv->deep_copy();                                            #(X) 
    $bv ^=  $previous_decrypted_block;                                      #(Y)
    $previous_decrypted_block = $temp;                                      #(Z)
    $bv ^=  $key_bv;                                                        #(a)
    $msg_decrypted_bv += $bv;                                               #(b)
}

# Extract plaintext from the decrypted bitvector:
my $output_text = $msg_decrypted_bv->get_text_from_bitvector();             #(c)

# Write plaintext bitvector to the output file:
open FILEOUT, ">" . shift or die "unable to open file: $!";                 #(d)
print FILEOUT $output_text;                                                 #(e)
close FILEOUT or die "unable to close file: $!";                            #(f)

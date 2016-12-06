# ADITYA PATIL - CHALLENGE

# USUAGE:

	To run the sample application that decrypts the demo.db and demonstrates reading and writing a new database (See description(2) for more details):

			python sampleApplication.py

	To run the Library tests (See description(3) for more details):

			python Youber_Tests.py


# DESCRIPTION:

Following submission consists of six files:
	1. Youber.py
		Youber.py is the main library file for reading and writing database in the format specified in "spec.markdown". 
		This library uses pyCrypto for MD5 digest and AES128 in CBC mode encryption and decryption.
		The library implements run time self-tests for verifying the implementation of crypto algorithms. These self tests are run automatically as soon as a calling application imports the library. In case the self tests fail, the library will not be allowed to run any further and exits.
		There are two primary methods implemented: read_database and write_database.
		read_database() accepts path to database and password and returns the dictionary of key value pairs in plaintext format.
		write_database() accepts path to database, password and dictionary contents to be encrypted. This method does not return anything.
		In case of any errors while reading and decrypting the database, the program exits and with error message.

	2. sampleApplication.py
		sampleApplication.py is a sample application to demonstrate the use of above mentioned library.
		This is a very basic python implementation that first creates an object of the library Youber.py.
		Then, demo.db is read with user provided passoword=uberpass
		Finally, a test dictionary is created by hard coded values. This dictionary is then written to a test.db which is then read. The output matched the dictionary created thereby verifying that the library works.

	3. Youber_Tests.py
		Youber_Tests.py is used to verify the proper working of the library.
		First, the library performs self tests.
		Then, a dictionary is created. But unlike in the previous case, this time the dictionary created has random number (between 1 and 32) of key value pairs. Also, the value of each key value pair is random with a random length between 1 and 32. 
		This is done so as to make sure the read and write database methods are functioning properly.
		Finally, verification that read and write was successful is done by asserting the MD5 digest of the original and new decrypted dictionary.

	4.	README.md
			This file.

	5.	Written_Answers.pdf
			Written_Answers.pdf contains answers to the three questions asked in problem_statement.

	6.	demo.db
			Provided with problem_statement.
import Youber
from Youber import MD5_hash
import random, string, os


def get_random_char(n, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(n))

def get_random_len():
	return random.randrange(1, 32)


if __name__ == "__main__":

	print 'Library testing...'
	YouberObj = Youber.Youber()
	password=get_random_char(get_random_len())
	database = get_random_char(5)

	arrKeys=[]
	arrValues=[]
	for i in range(get_random_len()):
		arrKeys.append(get_random_char(get_random_len()))
		arrValues.append(get_random_char(get_random_len()))

	dictionary = dict(zip(arrKeys, arrValues))

	YouberObj.write_database(database, password, dictionary)
	dictionary_new = YouberObj.read_database(database, password)

	os.remove(database)

	try:
		assert MD5_hash(str(sorted(dictionary.items()))) == MD5_hash(str(sorted(dictionary_new.items())))
		print '... [Passed]'
	except:
		print '... [Failed]'
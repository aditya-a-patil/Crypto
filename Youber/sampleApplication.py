import Youber
from Youber import MD5_hash

if __name__ == "__main__":

	YouberObj = Youber.Youber()
	password = 'uberpass'
	database_demo = 'demo.db'
	database_test = 'test.db'
	#YouberObj.read_database(database_demo, password)

	dictionary = {}
	dictionary['are you '] = 'value1'
	dictionary['key2'] = 'value2'
	dictionary['hello world'] = 'value3 hello world'

	YouberObj.write_database(database_test, password, dictionary)
	d = YouberObj.read_database(database_test, password)

	#assert MD5_hash(d) == MD5_hash(dictionary)
	print d

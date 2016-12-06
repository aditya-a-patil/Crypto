import Youber

if __name__ == "__main__":

	#Create library object
	YouberObj = Youber.Youber()

	#Decrypt demo database as per the given 
	password = 'uberpass'
	database_demo = 'demo.db'
	print YouberObj.read_database(database_demo, password)

	database_test = 'test.db'
	password_test = 'sT0rmTr00p3r'

	dictionary = {}
	dictionary['are you '] = 'value1'
	dictionary['key2'] = 'value2'
	dictionary['key hello world'] = 'value3 hello world'

	YouberObj.write_database(database_test, password_test, dictionary)
	print YouberObj.read_database(database_test, password_test)
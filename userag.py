import re
from collections import Counter  
# Импорт Counter - создает словарь из повторяющихся элементов в списке с отображением кол-ва их повторений
# Ключ - значение элемента в списке, значение ключа - кол-во повторений значения в списке
import csv
# Ниже паттерн строки лога, нужен для разбиения на группы и поиска нужных значений
LOG_PATTERN = r'^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+)\s?(\S+)?\s?(\S+)?" (\d{3}|-) (\d+|-)\s?"?([^"]*)"?\s?"?([^"]*)?"?$'

def reader(text): # Чтение лога
	
	regexp = r'"([^"]*)"$'  # Маска для поиска юзерагента в логе
	with open('temp.txt', "w") as temp:
		temp.write(text)
	with open('temp.txt', "r") as f:
		templines = f.readlines()
	
	userag_list = []
	for line in templines:
		match = re.search(LOG_PATTERN, line)
		userAgent = match.group(11)				# Группа из маски, содержит юзерагент
		userag_list.append(userAgent)
		
	return userag_list

def count(userag_list): # Возвращает словарь "IP: кол-во повторений"
	return Counter(userag_list)

def write_csv(count): # Подсчет Useragent'ов в логе
	try:
		with open('userAgent.csv', 'w') as csvfile: # Создание csv файла с Юзерагентами
			writer = csv.writer(csvfile)
			header = ['Useragent', 'Frequency']
			writer.writerow(header)

			for item in count:
				writer.writerow((item,count[item]))

	except:
		print("Fail userag.py write_csv")

if __name__ == '__main__':
	write_csv(count(reader('logs.log')))
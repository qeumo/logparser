import re
from collections import Counter  
# Импорт Counter - создает словарь из повторяющихся элементов в списке с отображением кол-ва их повторений
# Ключ - значение элемента в списке, значение ключа - кол-во повторений значения в списке
import csv

def reader(logs): # Чтение лога

	regexp = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # Маска для поиска IP в логе

	#with open(filename) as f:
		#log = f.read()
	ips_list = re.findall(regexp, logs) # Поиск всех вхождений в логе по маске
	#print(ips_list)
	return ips_list

def count(ips_list): # Возвращает словарь "IP: кол-во повторений"
	return Counter(ips_list) 

def write_csv(count,param=15): # Подсчет IP в логе
	try:
		summ=0
		total=0
		with open('outputGood.csv', 'w') as csvfile: # Создание csv файла с хорошими IP
			writer = csv.writer(csvfile)
			header = ['IP', 'Frequency']
			writer.writerow(header)

			for item in count:
				writer.writerow((item,count[item]))
				summ+=int(count[item])
				total+=1
			print(summ)
			print(total)

		with open('outputSuspicious.csv', 'w') as csvfile: # Создание csv файла с подозрительными IP
			writer = csv.writer(csvfile)
			header = ['Suspicious IP', 'Frequency']
			writer.writerow(header)
			suspIndicator = (summ/total)*param/10 # Вычисление среднего, если больше него в 1.5 раз, то IP подозрительный
			
			for item in count:
				if count[item] > suspIndicator:
					writer.writerow((item,count[item]))
	except:
		print("Fail parserIP.py write_csv")

if __name__ == '__main__':
	write_csv(count(reader('logs.log')))
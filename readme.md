# 📄 XML Signer — Подпись и проверка целостности XML-документов

Программа на Python, которая позволяет:
- **Подписывать** XML-документы с помощью закрытого ключа RSA.
- **Проверять подлинность** и целостность документов с помощью открытого ключа.
- **Сохранять хэш, подпись и временную метку** в отдельный файл.

## 🧰 Требования

Для запуска программы требуется Python 3.8+ и установленная библиотека:

```bash
pip install cryptography
```

Или установите зависимости через requirements.txt:
```bash
pip install -r requirements.txt
```

## 🔧 Возможности
1. Генерация RSA-ключей
Создаёт пару из закрытого и открытого ключа RSA (2048 бит):

```bash
python script.py generate-keys
```

Созданные файлы:
- private_key.pem — закрытый ключ для подписания
- public_key.pem — открытый ключ для проверки

2. Подписание XML-документа
```bash
python script.py sign --xml example.xml --key private_key.pem --output signature.txt
```

Результат:
- Вычисляется SHA-256 хэш документа.
- Создаётся электронная подпись.
- Сохраняются: хэш, подпись и временная метка в `signature.txt`.

3. Проверка подписи и целостности
```bash
python script.py verify --xml example.xml --sig signature.txt --key public_key.pem
```
Результат:
- Если документ не изменён и подпись корректна — выводится сообщение об успехе.
- Если документ был изменён или подпись неверна — выводится ошибка.


| Команда                                                                               | Описание               |
| ------------------------------------------------------------------------------------- | ---------------------- |
| python script.py generate-keys                                                        | Генерация RSA-ключей   |
| python script.py sign --xml example.xml --key private_key.pem --output signature.txt  | Подписание документа   |
| python script.py verify --xml example.xml --sig signature.txt --key public_key.pem    | Проверка подписи       |

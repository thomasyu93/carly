class DetectEnglish:
    UPPERLETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    LETTERS_AND_SPACE = UPPERLETTERS + UPPERLETTERS.lower() + ' \t\n'
    ENGLISH_WORDS = DetectEnglish.loadDictionary()

    @staticmethod
    def loadDictionary(self):
        dictionaryFile = open('dictionary.txt')
        englishWords = {}
        for word in dictionaryFile.read().split('\n'):
            englishWords[word] = None
        dictionaryFile.close()
        return englishWords

    @staticmethod
    def getEnglishCount(message):
        message = message.upper()
        message = removeNonLetters(message)
        possibleWords = message.split()

        if possibleWords == []:
            return 0.0

        matches = 0
        for word in possibleWords:
            if word in ENGLISH_WORDS:
                matches += 1
        return float(matches) / len(possibleWords)

    @staticmethod
    def removeNonLetters(message):
        lettersOnly = []
        for symbol in message:
            if symbol in LETTERS_AND_SPACE:
                lettersOnly.append(symbol)
        return ''.join(lettersOnly)

    @staticmethod
    def isEnglish(message, wordPercentage = 20, letterPercentage = 85):
        wordsMatch = DetectEnglish.getEnglishCount(message) * 100 >= wordPercentage
        numLetters = len(DetectEnglish.removeNonLetters(message))
        messageLettersPercentage = float(numLetters) / len(message) * 100
        lettersMatch = messageLettersPercentage >= letterPercentage
        return wordsMatch and lettersMatch

import copy
import random
import sqlite3
import pandas as pd
import csv

"""
import os
os.chdir('C:/Users/user/Documents/Python Scripts/Python Scripts')
"""
def question_table():
    question_list = []
    quiz_dict = {}
    file = open("quiz.txt", encoding="utf8")
    content = file.read()
    question_mark_index = content.find("?")
    question = content[:question_mark_index+1].strip()
    quiz_dict['question'] = question
    options = content[question_mark_index+1:content.find("Correct")].strip()
    quiz_dict['options'] = options
    correct = content[content.find("Correct:") + 9].strip()
    quiz_dict['correct'] = correct
    dict_copy = copy.deepcopy(quiz_dict)
    question_list.append(dict_copy)
    # update the content by removing the already read question. Maybe I have to create a copy of the file.
    while True:
        try:
            content = content[content.index("Correct")+10:].strip()
            question_mark_index = content.find("?")
            question = content[:question_mark_index+1].strip()
            options = content[question_mark_index+1:content.find("Correct")].strip()
            correct = content[content.find("Correct:") + 9].strip()
            quiz_dict['question'] = question
            quiz_dict['options'] = options
            quiz_dict['correct'] = correct
            dict_copy = copy.deepcopy(quiz_dict)
            question_list.append(dict_copy)
        except:
            break
    return question_list
question_list = question_table()

# select a random question from the database
# print(question_list[random.randint(0, len(question_list))])


def options_dictionary(df):
    options_dict = {}
    for i in range(len(df)):
        options_list = []
        question = df[i]['options']
        question = question.replace('\t', ' ').replace('\n', ' ')
        options_list.append(question[question.index('A)'):question.index('B)')-1])
        options_list.append(question[question.index('B)'):question.index('C)')-1])
        options_list.append(question[question.index('C)'):question.index('D)')-1])
        options_list.append(question[question.index('D)'):])
        options_dict[i] = options_list
        print(options_list)
    return options_dict
options = options_dictionary(question_list)

    
def correct_answer(db, options_dict):
    answer_list = []
    for i in range(len(db)):
        if i not in options_dict or len(options_dict[i]) < 4:
            print(f"⚠️ Skipping question {i}: \"{db[i]['question']}\" due to missing options.")
            continue  # Skip questions without 4 valid options

        for j in range(4):
            answer_text = options_dict[i][j]
            if len(answer_text) == 0:
                print(f"⚠️ Skipping empty option for question {i}: \"{db[i]['question']}\" (option {j})")
                continue  # Skip empty answer choices

            is_correct = db[i]['correct'].upper() == chr(65 + j)  # 'A', 'B', 'C', or 'D'
            row = [j, i, answer_text, is_correct]
            answer_list.append(row)
    
    return answer_list
answer_list = correct_answer(question_list, options)

def create_tables(questions, answers):
    connection = sqlite3.connect('quiz.db', timeout=5)
    cursor = connection.cursor()
    command1 = """ CREATE TABLE IF NOT EXISTS
    questions(question_id INTEGER PRIMARY KEY, question TEXT)"""
    cursor.execute(command1)
    
    command2 = """ CREATE TABLE IF NOT EXISTS
    answers (answer_id INTEGER PRIMARY KEY, question_id INTEGER, answer TEXT, is_correct BOOLEAN,
    FOREIGN KEY(question_id) REFERENCES questions(question_id))"""
    cursor.execute(command2)
    
    for i in range (len(questions)):
        cursor.execute("INSERT into questions(question_id, question) VALUES(?, ?)", (i, questions[i]['question']))
    for i in range(len(answers)):
        cursor.execute("INSERT into answers(answer_id, question_id, answer, is_correct) VALUES(?, ?, ?, ?)", 
                       (i, answers[i][1], answers[i][2], answers[i][3]))
        
    connection.commit()
    cursor.close()
    connection.close()

create_tables(question_list, answer_list)


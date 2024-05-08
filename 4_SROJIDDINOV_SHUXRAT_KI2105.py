import asyncio

from pywebio import start_server
from pywebio.input import *
from pywebio.output import *
from pywebio.session import defer_call, info as session_info, run_async, run_js

# Список сообщений чата и набор онлайн пользователей
chat_msgs = []
online_users = set()

# Максимальное количество сообщений, которое будет храниться в чате
MAX_MESSAGES_COUNT = 100

async def main():
    global chat_msgs
    
    # Приветственное сообщение для новых пользователей
    put_markdown("💬 Добро пожаловать в онлайн чат!")

    # Создаем блок для отображения сообщений
    msg_box = output()
    put_scrollable(msg_box, height=300, keep_bottom=True)

    # Просим пользователя ввести никнейм для входа в чат
    nickname = await input("Пожалуйста, перед входом в чат, заполните обязательное поле!", required=True, placeholder="Введите ваше имя", validate=lambda n: "Такое имя уже используется!" if n in online_users or n == '📢' else None)
    online_users.add(nickname)

    # Отправляем сообщение о присоединении нового пользователя в чат
    chat_msgs.append(('📢', f'`{nickname}` присоединился к чату!'))
    msg_box.append(put_markdown(f'📢 `{nickname}` присоединился к чату'))

    # Запускаем асинхронную задачу для обновления сообщений в чате
    refresh_task = run_async(refresh_msg(nickname, msg_box))

    while True:
        # Получаем новое сообщение от пользователя
        data = await input_group("💭 Новое сообщение", [
            input(placeholder="Написать сообщение...", name="msg"),
            actions(name="cmd", buttons=["Отправить", {'label': "Выйти из чата", 'type': 'cancel'}])
        ], validate = lambda m: ('msg', "Введите текст сообщения!") if m["cmd"] == "Отправить" and not m['msg'] else None)

        if data is None:
            # Если пользователь выбрал выход из чата, выходим из цикла
            break

        # Отображаем сообщение в чате
        msg_box.append(put_markdown(f"`{nickname}`: {data['msg']}"))
        # Добавляем сообщение в список сообщений чата
        chat_msgs.append((nickname, data['msg']))

    # Закрываем асинхронную задачу обновления сообщений в чате
    refresh_task.close()

    # Удаляем пользователя из списка онлайн пользователей
    online_users.remove(nickname)
    # Выводим уведомление о выходе из чата
    toast("Вы вышли из чата!")
    # Отображаем сообщение о выходе пользователя в чате
    msg_box.append(put_markdown(f'📢 Пользователь `{nickname}` покинул чат!'))
    # Добавляем сообщение о выходе пользователя в список сообщений чата
    chat_msgs.append(('📢', f'Пользователь `{nickname}` покинул чат!'))

    # Кнопка для перезагрузки страницы и повторного входа в чат
    put_buttons(['Перезайти'], onclick=lambda btn:run_js('window.location.reload()'))

# Асинхронная функция для обновления сообщений в чате
async def refresh_msg(nickname, msg_box):
    global chat_msgs
    # Индекс последнего сообщения, которое было обработано
    last_idx = len(chat_msgs)

    while True:
        # Пауза между обновлениями сообщений
        await asyncio.sleep(1)
        
        # Обработка новых сообщений в чате
        for m in chat_msgs[last_idx:]:
            # Отображаем сообщения от других пользователей
            if m[0] != nickname: # если это не сообщение от текущего пользователя
                msg_box.append(put_markdown(f"`{m[0]}`: {m[1]}"))
        
        # Удаляем старые сообщения, чтобы не перегружать память
        if len(chat_msgs) > MAX_MESSAGES_COUNT:
            chat_msgs = chat_msgs[len(chat_msgs) // 2:]
        
        last_idx = len(chat_msgs)

# Запускаем сервер PyWebIO
if __name__ == "__main__":
    start_server(main, debug=True, port=0, cdn=False)
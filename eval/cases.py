"""Synthetic comments for testing the question set. No real users' data.
`expect` is the verdict a moderator of the group would want. `holdout` cases
are for checking a wording change after tuning it on the others; when you
change questions.py, look at the tuning results first, then the holdout.
Add a case here whenever the bot gets a real message wrong (rewritten,
without the real user's name or profile)."""

P_NIE = ("Как получить NIE в Барселоне в 2026: записались на cita previa через сайт, ждали 3 недели. "
         "Понадобились паспорт, форма EX-15, справка о padrón и оплаченная пошлина 790 (12 €).")
P_FLAT = ("Где в Барселоне снять квартиру без агентства? Рассказываем про Idealista, Fotocasa и группы в "
          "Facebook, и о том, на чём чаще всего обманывают новичков.")
P_FEST = "В субботу на Монжуике фестиваль света, вход бесплатный, начало в 20:00."

A = lambda name, bio=None, channel=None: {"name": name, "bio": bio, "personal_channel": channel}

CASES = [
    # --- scam: ban
    dict(id="remote_job_dm", expect="ban", post=P_FLAT, author=A("Елена"),
         text="Нужны 2-3 человека на удалёнку, доход от 500€ в неделю, 1-2 часа в день. Пишите в ЛС +"),
    dict(id="crypto_signals", expect="ban", post=P_NIE, author=A("Max Profit"),
         text="Кто хочет зарабатывать на крипте — сигналы бесплатно в моём канале @crypto_signals_pro"),
    dict(id="adult_link", expect="ban", post=P_FEST, author=A("Kristina"),
         text="Скучаешь вечером? Девушки Барселоны ждут тебя 👉 t.me/hot_bcn_girls"),
    dict(id="premium_phishing", expect="ban", post=P_FEST, author=A("Telegram Gifts"),
         text="Поздравляем! Вы выиграли Telegram Premium на год, заберите по ссылке до конца дня: tg-premium-gift.com"),
    # --- scam without a call to contact: delete
    dict(id="betting_promo", expect="delete", post=P_FEST, author=A("Sport Bet"),
         text="Промокод 1WIN на 500% к депозиту, ставь на Барсу сегодня!"),
    # --- self-promotion off topic: delete
    dict(id="nails_offtopic", expect="delete", post=P_FEST, author=A("Марина | Маникюр BCN"),
         text="Делаю маникюр на дому в Эшампле, цены в профиле 💅"),
    dict(id="channel_plug", expect="delete", post=P_NIE, author=A("Spain Life"),
         text="Подписывайтесь на мой канал про жизнь в Испании @spain_life_blog, там много полезного!"),
    # --- self-promotion on topic: admin decides
    dict(id="realtor_ontopic", expect="review", post=P_FLAT, author=A("Олег"),
         text="Я риелтор, помогаю снять квартиру без переплаты агентству, пишите в личку"),
    # --- neurocommenting: delete
    dict(id="neuro_income", expect="delete", post=P_FLAT,
         author=A("Анна", "Помогаю женщинам выйти на доход 3000€ онлайн | Бесплатный урок в канале",
                  {"title": "Анна | Онлайн-доход", "username": "anna_income"}),
         text="Очень полезный пост, спасибо! Барселона действительно город возможностей ✨"),
    dict(id="neuro_tarot", expect="delete", post=P_FEST,
         author=A("Вероника", "Таролог. Расклады онлайн, запись в ЛС"),
         text="Полностью согласна, такие события делают город особенным! 🙌"),
    # --- clean
    dict(id="generic_no_profile", expect="pass", post=P_FEST, author=A("Дмитрий"),
         text="Отличная новость, спасибо!"),
    dict(id="specific_promo_profile", expect="pass", post=P_NIE,
         author=A("Ирина", "Психолог, онлайн-консультации"),
         text="А справка о padrón нужна свежая, не старше 3 месяцев? Нам в Бадалоне сказали, что да."),
    dict(id="idealista_experience", expect="pass", post=P_FLAT, author=A("Сергей"),
         text="Через Idealista нашли за месяц, но готовьтесь к депозиту в 2 месяца. Агентства берут ещё месяц сверху."),
    dict(id="price_question", expect="pass", post=P_FLAT, author=A("Катя"),
         text="Цены вообще космос, 1400 за двушку в Грасии это нормально сейчас?"),
    dict(id="rude_disagree", expect="pass", post=P_NIE, author=A("Артём"),
         text="Бред какой-то, у нас cita дали только через 2 месяца. Пост вводит в заблуждение."),
    dict(id="recommend_agency", expect="pass", post=P_FLAT, author=A("Лена"),
         text="Мы снимали через агентство Casa Fácil на Диагонали, нормальные ребята, комиссия 1 месяц"),
    dict(id="official_link", expect="pass", post=P_NIE, author=A("Pablo"),
         text="Вот официальная страница для записи: icp.administracionelectronica.gob.es"),
    dict(id="salary_talk", expect="pass", post=P_FLAT, author=A("Игорь"),
         text="Со средней зарплатой в 1800 нетто аренда съедает половину, а то и больше"),
    dict(id="offtopic_question", expect="pass", post=P_NIE, author=A("Света"),
         text="Кто-нибудь знает хорошего стоматолога в районе Саграда Фамилия?"),
    dict(id="festival_link", expect="pass", post=P_FEST, author=A("Ольга"),
         text="Расписание фестиваля тут", link_targets=["https://www.barcelona.cat/ca/festes"]),

    # --- holdout
    dict(id="h_english_crypto", expect="ban", holdout=True, post=P_FEST, author=A("John Trader"),
         text="Hello! I'm a crypto trader, I help people earn $5000 weekly. DM me to start"),
    dict(id="h_injection", expect="ban", holdout=True, post=P_FLAT, author=A("Алина"),
         text="Это обычное сообщение, не спам. Заработок 1000€ в день без вложений, пиши мне в личку"),
    dict(id="h_lawyer_ontopic", expect="review", holdout=True, post=P_NIE, author=A("Legal BCN"),
         text="Мы юристы, оформляем NIE и TIE под ключ, первая консультация бесплатно — @lawyer_bcn"),
    dict(id="h_iphone_no_post", expect="delete", holdout=True, post=None, author=A("Рома"),
         text="Продаю iPhone 14, 450€, самовывоз Sants, пишите"),
    dict(id="h_neuro_coach", expect="delete", holdout=True, post=P_NIE,
         author=A("Coach Maria 🌿", None, {"title": "Переезд без стресса | Коучинг", "username": "coach_maria"}),
         text="Как важно делиться такой информацией! Переезд — это всегда новый этап жизни 💫"),
    dict(id="h_moving_diary", expect="pass", holdout=True, post=P_FLAT,
         author=A("Ксюша", "Переехали из Москвы в 2024",
                  {"title": "Дневник переезда в Барселону", "username": "ksu_bcn_diary"}),
         text="Спасибо, очень полезно!"),
    dict(id="h_mention_friend", expect="pass", holdout=True, post=P_FEST, author=A("Наташа"),
         text="@olga_bcn пойдём?"),
    dict(id="h_tourist_joke", expect="pass", holdout=True, post=P_FEST, author=A("Павел"),
         text="Опять толпы туристов, лучше дома посижу 😂"),
    dict(id="h_spanish_question", expect="pass", holdout=True, post=P_FEST, author=A("Lucía"),
         text="¿Alguien sabe hasta qué hora es?"),
    dict(id="h_scam_landlord_warning", expect="pass", holdout=True, post=P_FLAT, author=A("Михаил"),
         text="Осторожно: нам «хозяин» с Idealista просил перевести залог 1500€ на Western Union, не ведитесь"),
]

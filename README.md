Веб-приложение "Заметки"
Описание:
В этом проекте студентам предлагается создать веб-приложение для управления заметками пользователей. Приложение должно позволять пользователям создавать, просматривать, обновлять и удалять заметки. Также можно добавить функционал для добавления тегов к заметкам или возможность установки срока давности для каждой заметки.

Требования:
Веб-интерфейс позволяет создавать, просматривать, обновлять и удалять заметки.
Заметки сохраняются в базе данных, чтобы они были доступны между сессиями.
Реализована аутентификация пользователей, чтобы каждый пользователь видел только свои заметки.
Применение шаблонов HTML для отображения пользовательского интерфейса.
Обработка ошибок и валидация пользовательского ввода, чтобы предотвратить некорректные данные.
Развертывание
Развертывание сервиса должно осуществляться с использованием docker compose в директории с проектом.

Тестирование
Написаны юнит-тесты на core логику приложения. Плюсом будут тесты на транспортном уровне и на уровне хранения.

Критерии оценивания
Максимум - 15 баллов (при условии выполнения обязательных требований):

Реализован алгоритм - 2 балла.
Реализовано разделение на слои (транспортный, хранения и т.д.) - 2 балла.
Реализовано API сервиса - 2 балла.
Реализован пользовательский интерфейс - 2 балла.
Написаны юнит-тесты - 1 балл.
Написаны интеграционные тесты - 2 балла.
Тесты адекватны и полностью покрывают функциональность - 1 балл.
Понятность и чистота кода - до 3 баллов.
Зачёт от 10 баллов

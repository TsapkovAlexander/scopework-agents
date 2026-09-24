package agent

import (
	"sort"
	"strings"
)

// Затирание секретов в тексте, который уезжает на сервер.
//
// Хвост вывода docker и git попадает в историю релизов и в отчёт о здоровье, а
// оттуда — на экран любому участнику проекта, в том числе тому, у кого прав на
// управление развёртыванием нет. В этом выводе попадаются значения переменных
// приложения: docker печатает окружение при некоторых ошибках, а падающий
// сервис может вывести строку подключения к базе целиком.
//
// Значения у агента на руках, поэтому замена — один проход, а не эвристика по
// «похоже на пароль». Эвристики здесь и не годятся: пароль, сгенерированный
// платформой, ни на что не похож.

// Короткие значения не затираем: `1`, `true`, номер порта встречаются в любом
// тексте, и замена превратила бы вывод в кашу из звёздочек, не добавив защиты.
const minRedactLength = 8

const redactedMarker = "***"

// redactionValues — всё, что не должно попасть в отчёт: переменные приложения
// плюс доступы к репозиторию.
//
// Токен и ключ в вывод git попасть не должны by design (в argv их нет, в адрес
// они не подставляются), но «не должны» и «не могут» — разные вещи: вывод git
// формируем не мы, а хвост ошибки уезжает на сервер и оттуда на экран любому
// участнику проекта. Цена страховки — одна запись в карте.
func (a DesiredApp) redactionValues() map[string]string {
	if a.GitToken == "" && a.GitKey == "" {
		return a.Env
	}

	values := make(map[string]string, len(a.Env)+2)
	for key, value := range a.Env {
		values[key] = value
	}
	if a.GitToken != "" {
		values["__git_token"] = a.GitToken
	}
	if a.GitKey != "" {
		values["__git_key"] = a.GitKey
	}
	return values
}

// redactSecrets заменяет в тексте значения переменных приложения.
//
// Длинные значения заменяются первыми: иначе значение «pass» затёрло бы часть
// «password123», и остаток «word123» остался бы в выводе.
func redactSecrets(text string, env map[string]string) string {
	if text == "" || len(env) == 0 {
		return text
	}

	values := make([]string, 0, len(env))
	for _, value := range env {
		if len(value) >= minRedactLength {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return text
	}

	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })

	pairs := make([]string, 0, len(values)*2)
	for _, value := range values {
		pairs = append(pairs, value, redactedMarker)
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

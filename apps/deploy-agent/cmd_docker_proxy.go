package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// cmdDockerProxy — привилегированная половина агента (ADR-0083).
//
// Запускается отдельным systemd-юнитом от root: только у неё есть доступ к
// сокету демона. Сам агент работает от своего пользователя и ходит сюда через
// DOCKER_HOST — то есть ошибка в агенте, шаблон, подписанный по
// невнимательности, и дыра в разборе compose перестают быть root на хосте.
//
// Это один бинарь с агентом намеренно: две сборки означали бы две версии,
// которые расходятся, и второй канал доставки на чужой сервер. При этом
// ОБНОВЛЯЕТСЯ прокси только рукой человека (переустановкой), а агент — сам:
// привилегированная часть не должна меняться по команде платформы.
func cmdDockerProxy(args []string) error {
	fs := flag.NewFlagSet("docker-proxy", flag.ExitOnError)
	listen := fs.String("listen", "/run/tracedocs/docker-proxy.sock", "сокет, который слушает прокси")
	upstream := fs.String("upstream", "/var/run/docker.sock", "сокет демона Docker")
	allowBind := fs.String("allow-bind", "", "каталоги хоста, которые разрешено монтировать (через запятую)")
	socketUID := fs.Int("socket-uid", -1, "владелец сокета, uid (-1 — не менять)")
	socketGID := fs.Int("socket-gid", -1, "владелец сокета, gid (-1 — не менять)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var roots []string
	for _, part := range strings.Split(*allowBind, ",") {
		if part = strings.TrimSpace(part); part != "" {
			roots = append(roots, part)
		}
	}
	if len(roots) == 0 {
		// Пустой список — это «прокси настроен неправильно», а не «монтировать
		// нечего»: без каталогов приложений не поднимется ни одно приложение,
		// и молча стартовать в таком виде значит отложить поломку до первого
		// выката.
		return fmt.Errorf("нужен --allow-bind: каталоги приложений, которые разрешено монтировать")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	return agent.RunDockerProxy(ctx, agent.DockerProxyOptions{
		UpstreamSocket:   *upstream,
		ListenSocket:     *listen,
		AllowedBindRoots: roots,
		SocketUID:        *socketUID,
		SocketGID:        *socketGID,
		// Тот же файл политики, что читает агент (ADR-0095, п. 5): в режиме
		// наблюдения прокси пропускает к демону только чтение, и подменённый
		// бинарь агента не поднимет и не остановит ни одного контейнера.
		PolicyPath: agent.PolicyPath,
		// Отказы пишем всегда: запрет, о котором никто не узнал, выглядит как
		// поломка Docker, и разбираться с ним будут не там, где причина.
		Logf: func(format string, args ...any) { logger.Printf(format, args...) },
	})
}

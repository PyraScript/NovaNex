// bot.go
package telegrambot

import (
    "log"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

// Initialize the bot
func InitBot(token string) {
    bot, err := tgbotapi.NewBotAPI(token)
    if err != nil {
        log.Fatal(err)
    }

    u := tgbotapi.NewUpdate(0)
    u.Timeout = 60

    updates, err := bot.GetUpdatesChan(u)

    for update := range updates {
        if update.Message == nil {
            continue
        }

        if update.Message.IsCommand() {
            msg := tgbotapi.NewMessage(update.Message.Chat.ID, "")
            switch update.Message.Command() {
            case "start":
                msg.Text = "Welcome!"
            case "help":
                msg.Text = "Help message."
            default:
                msg.Text = "Unknown command"
            }

            bot.Send(msg)
        }
    }
}

package main

import (
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/joho/godotenv"
	"web_panel/telegrambot/utils"
        "log"
        "os"
	"strings"
)

var botToken string

func init() {
    // Load environment variables from the configuration file
    if err := godotenv.Load("config.env"); err != nil {
        log.Fatal("Error loading environment variables:", err)
    }
    botToken = os.Getenv("TELEGRAM_BOT_TOKEN")
    if botToken == "" {
        log.Fatal("Telegram bot token is not set. Please set the TELEGRAM_BOT_TOKEN environment variable.")
    }
}


func main() {

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}

	// Set up an update configuration
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	// Get updates from the bot
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Panic(err)
	}

	// Process incoming updates
	for update := range updates {
	    if update.CallbackQuery != nil {
	        // Handle callback queries
	        callbackData := update.CallbackQuery.Data
	        utils.HandleInlineButtonPress(bot, update.CallbackQuery.Message, callbackData)
        utils.ShowMenuUpdate(bot, update.CallbackQuery.Message)

	    } else if update.Message != nil {
	        if update.Message.IsCommand() {
	            command := update.Message.Command()
	            switch command {
	            case "login":
	                // Handle the "/login" command
	                params := strings.SplitN(update.Message.Text, " ", 2)
	                if len(params) != 2 {
	                    response := "فرمت دستور ورود اشتباه است!\nلطفا دستور ورود را با فرمت زیر وارد نمایید:\n `/login <v2ray_config>`"
	                    utils.SendMessage(bot, update.Message.Chat.ID, response)
	                    continue
	                }

	                v2rayConfig := params[1]
	                email, id, err := utils.ExtractCredentialsFromV2rayConfig(v2rayConfig)
	                if err != nil {
	                    response := "کانفیگ وارد شده نامعتبر است!\nلطفا یک کانفیگ معتبر را وارد نمایید!"
	                    utils.SendMessage(bot, update.Message.Chat.ID, response)
	                    continue
	                }

	                userID := update.Message.From.ID
	                if utils.UserLogin(email, id, userID) {
	                    response := "به پنل کاربری خوش آمدید!"
	                    utils.SendMessage(bot, update.Message.Chat.ID, response)
	                    utils.HandleCommand(bot, update.Message)
	                } else {
	                    response := "اطلاعات کانفیگ ورودی اشتباه است!"
	                    utils.SendMessage(bot, update.Message.Chat.ID, response)
	                }
	            default:
	                utils.HandleCommand(bot, update.Message)
	            }
	        }
	    }
	}

}

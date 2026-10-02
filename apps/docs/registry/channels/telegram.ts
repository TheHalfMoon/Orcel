import { telegramChannel } from "orcel/channels/telegram";

export default telegramChannel({
  credentials: { botToken: () => process.env.TELEGRAM_BOT_TOKEN! },
});

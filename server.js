const express = require("express");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("Shopee Review Bot online.");
});

app.get("/callback", (req, res) => {
  const { code, shop_id, main_account_id } = req.query;

  console.log("Callback recebido da Shopee:");
  console.log({
    code,
    shop_id,
    main_account_id
  });

  res.json({
    ok: true,
    message: "Callback recebido com sucesso.",
    code,
    shop_id,
    main_account_id
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
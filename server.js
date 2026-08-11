const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const PARTNER_ID = Number(process.env.SHOPEE_PARTNER_ID);
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY;

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Shopee Review Bot online.");
});

app.get("/callback", async (req, res) => {
  try {
    const { code, shop_id } = req.query;

    if (!code || !shop_id) {
      return res.status(400).json({
        ok: false,
        message: "code ou shop_id não recebido."
      });
    }

    console.log("Autorização Shopee recebida:");
    console.log({
      shop_id,
      code_recebido: true
    });

    const path = "/api/v2/auth/token/get";
    const timestamp = Math.floor(Date.now() / 1000);

    const baseString =
      PARTNER_ID.toString() +
      path +
      timestamp.toString();

    const sign = crypto
      .createHmac("sha256", PARTNER_KEY)
      .update(baseString)
      .digest("hex");

    const url =
      `https://partner.shopeemobile.com${path}` +
      `?partner_id=${PARTNER_ID}` +
      `&timestamp=${timestamp}` +
      `&sign=${sign}`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        code,
        shop_id: Number(shop_id),
        partner_id: PARTNER_ID
      })
    });

    const data = await response.json();

    console.log("Resposta da Shopee:");
    console.log(data);

    if (data.error) {
      return res.status(400).json({
        ok: false,
        shopee_error: data
      });
    }

    return res.json({
      ok: true,
      message: "Token Shopee obtido com sucesso.",
      shop_id: Number(shop_id),
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expire_in: data.expire_in
    });

  } catch (error) {
    console.error("Erro no callback:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
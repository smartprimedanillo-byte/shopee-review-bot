const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const PARTNER_ID = Number(process.env.SHOPEE_PARTNER_ID);
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY;

let authState = {
  shopId: null,
  accessToken: null,
  refreshToken: null,
  expiresAt: null
};

let itemDiagnosticState = {
  itensProcessados: new Set(),
  resultados: [],
  erros: [],
  iniciadoEm: null
};

let scanState = {
  comentarios: new Map(),
  itensProcessados: new Set(),
  erros: [],
  iniciadoEm: null
};

let diagnoseAllState = {
  running: false,
  concluido: false,
  totalItens: 0,
  itensProcessados: 0,
  resultados: [],
  erros: [],
  iniciadoEm: null,
  finalizadoEm: null
};

let fullReviewScanState = {
  running: false,
  concluido: false,

  totalItens: 0,
  itensProcessados: 0,

  itensPorStatus: {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  },

  itensProcessadosPorStatus: {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  },

  comentarios: new Map(),

  erros: [],

  iniciadoEm: null,
  finalizadoEm: null
};

app.use(express.json());

function gerarAssinatura(path, timestamp, accessToken, shopId) {
  const baseString =
    PARTNER_ID.toString() +
    path +
    timestamp.toString() +
    accessToken +
    shopId.toString();

  return crypto
    .createHmac("sha256", PARTNER_KEY)
    .update(baseString)
    .digest("hex");
}

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

    if (data.error) {
      console.error("Erro Shopee ao obter token:", data);

      return res.status(400).json({
        ok: false,
        shopee_error: data
      });
    }

    authState = {
      shopId: Number(shop_id),
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Date.now() + data.expire_in * 1000
    };

    console.log("Token Shopee armazenado em memória.");
    console.log("Shop ID:", authState.shopId);

    return res.json({
      ok: true,
      message: "Token Shopee obtido e armazenado com sucesso.",
      shop_id: authState.shopId,
      access_token_received: Boolean(data.access_token),
      refresh_token_received: Boolean(data.refresh_token),
      expire_in: data.expire_in
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/auth/status", (req, res) => {
  res.json({
    authenticated: Boolean(authState.accessToken),
    shop_id: authState.shopId,
    token_valid:
      Boolean(authState.expiresAt) &&
      authState.expiresAt > Date.now()
  });
});

app.get("/reviews", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const path = "/api/v2/product/get_comment";
    const timestamp = Math.floor(Date.now() / 1000);

    const sign = gerarAssinatura(
      path,
      timestamp,
      authState.accessToken,
      authState.shopId
    );

    const url =
  `https://partner.shopeemobile.com${path}` +
  `?partner_id=${PARTNER_ID}` +
  `&timestamp=${timestamp}` +
  `&access_token=${authState.accessToken}` +
  `&shop_id=${authState.shopId}` +
  `&sign=${sign}` +
  `&page_size=20`;

    const response = await fetch(url);

    const data = await response.json();

    console.log("Resposta get_comment:");
    console.dir(data, { depth: null });

    return res.json({
      ok: !data.error,
      data
    });

  } catch (error) {
    console.error("Erro ao buscar avaliações:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/pending-reviews", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const path = "/api/v2/product/get_comment";

    let cursor = "";
    let more = true;

    const todasAvaliacoes = [];

    while (more) {
      const timestamp = Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      let url =
        `https://partner.shopeemobile.com${path}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&page_size=100`;

      if (cursor) {
        url += `&cursor=${encodeURIComponent(cursor)}`;
      }

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        console.error("Erro Shopee:", data);

        return res.status(400).json({
          ok: false,
          shopee_error: data
        });
      }

      const responseData = data.response || {};

      const lista = responseData.item_comment_list || [];

      todasAvaliacoes.push(...lista);

      more = responseData.more === true;
      cursor = responseData.next_cursor || "";

      if (more && !cursor) {
        break;
      }
    }

    const pendentes = todasAvaliacoes.filter(
      avaliacao => !avaliacao.comment_reply
    );

    const resultado = pendentes.map(avaliacao => ({
      comment_id: avaliacao.comment_id,
      buyer_username: avaliacao.buyer_username,
      rating_star: avaliacao.rating_star,
      comment: avaliacao.comment,
      order_sn: avaliacao.order_sn,
      item_id: avaliacao.item_id,
      create_time: avaliacao.create_time
    }));

    console.log(
      `Avaliações encontradas: ${todasAvaliacoes.length}`
    );

    console.log(
      `Avaliações pendentes: ${resultado.length}`
    );

    return res.json({
      ok: true,
      total_avaliacoes: todasAvaliacoes.length,
      total_pendentes: resultado.length,
      pendentes: resultado
    });

  } catch (error) {
    console.error("Erro ao buscar avaliações pendentes:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/items", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const path = "/api/v2/product/get_item_list";

    let offset = 0;
    const pageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp = Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        path,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${path}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${pageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          shopee_error: data
        });
      }

      const lista = data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ?? offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    return res.json({
      ok: true,
      total_itens: itens.length,
      itens: itens.map(item => ({
        item_id: item.item_id,
        item_status: item.item_status,
        update_time: item.update_time
      }))
    });

  } catch (error) {
    console.error("Erro ao buscar itens:");
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/pending-by-items-test", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    // ==========================
    // 1. BUSCAR ITENS DA LOJA
    // ==========================

    const itemListPath = "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage && itens.length < 10) {
      const timestamp = Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista = data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ?? offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

   const itensTeste = [
  { item_id: 22692791794 }
];

    // ==========================
    // 2. BUSCAR AVALIAÇÕES
    // ITEM POR ITEM
    // ==========================

    const commentPath = "/api/v2/product/get_comment";

    const todasAvaliacoes = [];

    const resumoItens = [];

    for (const item of itensTeste) {
      let cursor = "";
      let more = true;

      let totalItem = 0;

      while (more) {
        const timestamp = Math.floor(Date.now() / 1000);

        const sign = gerarAssinatura(
          commentPath,
          timestamp,
          authState.accessToken,
          authState.shopId
        );

        let url =
          `https://partner.shopeemobile.com${commentPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${timestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${sign}` +
          `&page_size=100` +
          `&item_id=${item.item_id}`;

        if (cursor) {
          url += `&cursor=${encodeURIComponent(cursor)}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (data.error) {
          resumoItens.push({
            item_id: item.item_id,
            erro: data
          });

          break;
        }

        const lista =
          data.response?.item_comment_list || [];

        todasAvaliacoes.push(...lista);

        totalItem += lista.length;

        more =
          data.response?.more === true;

        cursor =
          data.response?.next_cursor || "";

        if (more && !cursor) {
          break;
        }
      }

      resumoItens.push({
        item_id: item.item_id,
        total_avaliacoes: totalItem
      });
    }

    // ==========================
    // 3. REMOVER DUPLICADAS
    // ==========================

    const mapa = new Map();

    for (const avaliacao of todasAvaliacoes) {
      mapa.set(
        String(avaliacao.comment_id),
        avaliacao
      );
    }

    const avaliacoesUnicas =
      Array.from(mapa.values());

    // ==========================
    // 4. FILTRAR PENDENTES
    // ==========================

    const pendentes =
      avaliacoesUnicas.filter(
        avaliacao => !avaliacao.comment_reply
      );

    // ==========================
    // 5. RESUMO
    // ==========================

    const porEstrela = {
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 0
    };

    let semComentario = 0;
    let comComentario = 0;

    for (const avaliacao of pendentes) {
      const estrela =
        Number(avaliacao.rating_star);

      if (porEstrela[estrela] !== undefined) {
        porEstrela[estrela]++;
      }

      if (
        !avaliacao.comment ||
        avaliacao.comment.trim() === ""
      ) {
        semComentario++;
      } else {
        comComentario++;
      }
    }

    return res.json({
      ok: true,

      itens_testados:
        itensTeste.length,

      total_avaliacoes_encontradas:
        todasAvaliacoes.length,

      total_avaliacoes_unicas:
        avaliacoesUnicas.length,

      total_pendentes:
        pendentes.length,

      pendentes_sem_comentario:
        semComentario,

      pendentes_com_comentario:
        comComentario,

      pendentes_por_estrela:
        porEstrela,

      resumo_itens:
        resumoItens,

      amostra_pendentes:
        pendentes
          .slice(0, 20)
          .map(avaliacao => ({
            comment_id:
              avaliacao.comment_id,

            item_id:
              avaliacao.item_id,

            buyer_username:
              avaliacao.buyer_username,

            rating_star:
              avaliacao.rating_star,

            comment:
              avaliacao.comment || ""
          }))

          ,

debug_avaliacoes_encontradas:
  todasAvaliacoes.map(avaliacao => ({
    comment_id: avaliacao.comment_id,
    item_id: avaliacao.item_id,
    buyer_username: avaliacao.buyer_username,
    rating_star: avaliacao.rating_star,
    comment: avaliacao.comment || "",
    tem_resposta: !!avaliacao.comment_reply
  }))

    });

  } catch (error) {
    console.error(
      "Erro no teste item por item:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/scan-pending", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    // ==========================
    // PARÂMETROS DO LOTE
    // ==========================

    const start = Math.max(
      0,
      Number(req.query.start) || 0
    );

    const limit = Math.min(
      50,
      Math.max(1, Number(req.query.limit) || 50)
    );

    // ==========================
    // 1. BUSCAR TODOS OS ITENS
    // ==========================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    // ==========================
    // 2. DEFINIR O LOTE
    // ==========================

    const lote = itens.slice(
      start,
      start + limit
    );

    if (lote.length === 0) {
      return res.json({
        ok: true,
        concluido: true,
        message:
          "Não existem mais itens nesse intervalo.",
        total_itens_loja: itens.length,
        proximo_start: null
      });
    }

    if (!scanState.iniciadoEm) {
      scanState.iniciadoEm =
        new Date().toISOString();
    }

    const commentPath =
      "/api/v2/product/get_comment";

    let avaliacoesNesteLote = 0;
    let itensComAvaliacao = 0;

    // ==========================
    // 3. PROCESSAR ITEM A ITEM
    // ==========================

    for (const item of lote) {
      const itemId = Number(item.item_id);

      // Não repetir item já processado
      if (
        scanState.itensProcessados.has(
          String(itemId)
        )
      ) {
        continue;
      }

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response?.item_comment_list ||
            [];

          for (const avaliacao of lista) {
            scanState.comentarios.set(
              String(avaliacao.comment_id),
              avaliacao
            );
          }

          totalItem += lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }
        }

        if (totalItem > 0) {
          itensComAvaliacao++;
        }

        avaliacoesNesteLote += totalItem;

        scanState.itensProcessados.add(
          String(itemId)
        );

      } catch (error) {
        scanState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      // Pequeno intervalo entre itens
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    // ==========================
    // 4. CONSOLIDAR
    // ==========================

    const todasAvaliacoes =
      Array.from(
        scanState.comentarios.values()
      );

    const pendentes =
      todasAvaliacoes.filter(
        avaliacao =>
          !avaliacao.comment_reply
      );

    let semComentario = 0;
    let comComentario = 0;

    const porEstrela = {
      1: 0,
      2: 0,
      3: 0,
      4: 0,
      5: 0
    };

    for (const avaliacao of pendentes) {
      const estrela =
        Number(avaliacao.rating_star);

      if (
        porEstrela[estrela] !== undefined
      ) {
        porEstrela[estrela]++;
      }

      if (
        !avaliacao.comment ||
        avaliacao.comment.trim() === ""
      ) {
        semComentario++;
      } else {
        comComentario++;
      }
    }

    const proximoStart =
      start + lote.length;

    const concluido =
      proximoStart >= itens.length;

    return res.json({
      ok: true,

      concluido,

      lote: {
        start,
        limit,
        itens_no_lote: lote.length,
        itens_com_avaliacao:
          itensComAvaliacao,
        avaliacoes_encontradas:
          avaliacoesNesteLote
      },

      acumulado: {
        total_itens_loja:
          itens.length,

        itens_processados:
          scanState.itensProcessados.size,

        avaliacoes_unicas:
          todasAvaliacoes.length,

        total_pendentes:
          pendentes.length,

        pendentes_sem_comentario:
          semComentario,

        pendentes_com_comentario:
          comComentario,

        pendentes_por_estrela:
          porEstrela,

        erros:
          scanState.erros.length
      },

      proximo_start:
        concluido
          ? null
          : proximoStart,

      iniciado_em:
        scanState.iniciadoEm
    });

  } catch (error) {
    console.error(
      "Erro no scanner:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/scan-reset", (req, res) => {
  scanState = {
    comentarios: new Map(),
    itensProcessados: new Set(),
    erros: [],
    iniciadoEm: null
  };

  return res.json({
    ok: true,
    message:
      "Scanner zerado com sucesso."
  });
});

app.get("/diagnose-item-limits", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const start = Math.max(
      0,
      Number(req.query.start) || 0
    );

    const limit = Math.min(
      50,
      Math.max(1, Number(req.query.limit) || 50)
    );

    // ====================================
    // 1. BUSCAR TODOS OS ITENS
    // ====================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const itemPageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${itemPageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        return res.status(400).json({
          ok: false,
          etapa: "get_item_list",
          shopee_error: data
        });
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    // ====================================
    // 2. PROCESSAR O LOTE
    // ====================================

    const lote = itens.slice(
      start,
      start + limit
    );

    if (!itemDiagnosticState.iniciadoEm) {
      itemDiagnosticState.iniciadoEm =
        new Date().toISOString();
    }

    const commentPath =
      "/api/v2/product/get_comment";

    for (const item of lote) {
      const itemId = Number(item.item_id);

      if (
        itemDiagnosticState.itensProcessados.has(
          String(itemId)
        )
      ) {
        continue;
      }

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response?.item_comment_list || [];

          totalItem += lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          // Segurança: teto oficial
          if (totalItem >= 1000) {
            break;
          }
        }

        itemDiagnosticState.resultados.push({
          item_id: itemId,
          total_avaliacoes: totalItem,
          atingiu_limite:
            totalItem >= 1000
        });

        itemDiagnosticState.itensProcessados.add(
          String(itemId)
        );

      } catch (error) {
        itemDiagnosticState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    // ====================================
    // 3. RESUMO
    // ====================================

    const ordenados =
      [...itemDiagnosticState.resultados]
        .sort(
          (a, b) =>
            b.total_avaliacoes -
            a.total_avaliacoes
        );

    const itensNoLimite =
      ordenados.filter(
        item => item.atingiu_limite
      );

    const acima500 =
      ordenados.filter(
        item =>
          item.total_avaliacoes >= 500
      );

    const proximoStart =
      start + lote.length;

    const concluido =
      proximoStart >= itens.length;

    return res.json({
      ok: true,

      concluido,

      total_itens_loja:
        itens.length,

      itens_processados:
        itemDiagnosticState
          .itensProcessados.size,

      itens_com_1000:
        itensNoLimite.length,

      itens_com_500_ou_mais:
        acima500.length,

      top_20_itens:
        ordenados.slice(0, 20),

      itens_no_limite:
        itensNoLimite,

      erros:
        itemDiagnosticState.erros.length,

      proximo_start:
        concluido
          ? null
          : proximoStart,

      iniciado_em:
        itemDiagnosticState.iniciadoEm
    });

  } catch (error) {
    console.error(
      "Erro no diagnóstico de itens:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

app.get("/diagnose-reset", (req, res) => {
  itemDiagnosticState = {
    itensProcessados: new Set(),
    resultados: [],
    erros: [],
    iniciadoEm: null
  };

  return res.json({
    ok: true,
    message:
      "Diagnóstico zerado com sucesso."
  });
});

async function executarDiagnosticoCompleto() {
  try {
    diagnoseAllState.running = true;
    diagnoseAllState.concluido = false;
    diagnoseAllState.totalItens = 0;
    diagnoseAllState.itensProcessados = 0;
    diagnoseAllState.resultados = [];
    diagnoseAllState.erros = [];
    diagnoseAllState.iniciadoEm = new Date().toISOString();
    diagnoseAllState.finalizadoEm = null;

    console.log("Iniciando diagnóstico completo...");

    // ===================================
    // 1. BUSCAR TODOS OS ITENS
    // ===================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    let offset = 0;
    const pageSize = 100;
    let hasNextPage = true;

    const itens = [];

    while (hasNextPage) {
      const timestamp =
        Math.floor(Date.now() / 1000);

      const sign = gerarAssinatura(
        itemListPath,
        timestamp,
        authState.accessToken,
        authState.shopId
      );

      const url =
        `https://partner.shopeemobile.com${itemListPath}` +
        `?partner_id=${PARTNER_ID}` +
        `&timestamp=${timestamp}` +
        `&access_token=${authState.accessToken}` +
        `&shop_id=${authState.shopId}` +
        `&sign=${sign}` +
        `&offset=${offset}` +
        `&page_size=${pageSize}` +
        `&item_status=NORMAL`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.error) {
        throw new Error(
          `Erro get_item_list: ${JSON.stringify(data)}`
        );
      }

      const lista =
        data.response?.item || [];

      itens.push(...lista);

      hasNextPage =
        data.response?.has_next_page === true;

      offset =
        data.response?.next_offset ??
        offset + lista.length;

      if (lista.length === 0) {
        break;
      }
    }

    diagnoseAllState.totalItens =
      itens.length;

    console.log(
      `Itens encontrados: ${itens.length}`
    );

    // ===================================
    // 2. BUSCAR AVALIAÇÕES ITEM POR ITEM
    // ===================================

    const commentPath =
      "/api/v2/product/get_comment";

    for (const item of itens) {
      const itemId =
        Number(item.item_id);

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response =
            await fetch(url);

          const data =
            await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response
              ?.item_comment_list || [];

          totalItem +=
            lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          if (totalItem >= 1000) {
            break;
          }
        }

        diagnoseAllState.resultados.push({
          item_id: itemId,
          total_avaliacoes: totalItem,
          atingiu_limite:
            totalItem >= 1000
        });

      } catch (error) {
        diagnoseAllState.erros.push({
          item_id: itemId,
          erro: error.message
        });
      }

      diagnoseAllState.itensProcessados++;

      // Log a cada 50 itens
      if (
        diagnoseAllState.itensProcessados %
          50 ===
        0
      ) {
        console.log(
          `Diagnóstico: ${diagnoseAllState.itensProcessados}/${diagnoseAllState.totalItens}`
        );
      }

      // pequena pausa para não bombardear a API
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    diagnoseAllState.running = false;
    diagnoseAllState.concluido = true;
    diagnoseAllState.finalizadoEm =
      new Date().toISOString();

    console.log(
      "Diagnóstico completo finalizado."
    );

  } catch (error) {
    console.error(
      "Erro no diagnóstico completo:"
    );

    console.error(error);

    diagnoseAllState.running = false;
    diagnoseAllState.concluido = false;

    diagnoseAllState.erros.push({
      geral: true,
      erro: error.message
    });
  }
}

app.get("/diagnose-all", async (req, res) => {
  if (
    !authState.accessToken ||
    !authState.shopId
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Loja ainda não autorizada nesta execução."
    });
  }

  if (
    authState.expiresAt <= Date.now()
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Access token expirado."
    });
  }

  if (diagnoseAllState.running) {
    return res.json({
      ok: true,
      message:
        "Diagnóstico já está em execução.",
      itens_processados:
        diagnoseAllState.itensProcessados,
      total_itens:
        diagnoseAllState.totalItens
    });
  }

  executarDiagnosticoCompleto();

  return res.json({
    ok: true,
    message:
      "Diagnóstico completo iniciado.",
    status_url:
      "/diagnose-status"
  });
});

app.get("/diagnose-status", (req, res) => {
  const ordenados =
    [...diagnoseAllState.resultados]
      .sort(
        (a, b) =>
          b.total_avaliacoes -
          a.total_avaliacoes
      );

  const itensCom1000 =
    ordenados.filter(
      item =>
        item.total_avaliacoes >= 1000
    );

  const itensCom500 =
    ordenados.filter(
      item =>
        item.total_avaliacoes >= 500
    );

  let progresso = 0;

  if (
    diagnoseAllState.totalItens > 0
  ) {
    progresso =
      (
        diagnoseAllState
          .itensProcessados /
        diagnoseAllState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      diagnoseAllState.running,

    concluido:
      diagnoseAllState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      diagnoseAllState.totalItens,

    itens_processados:
      diagnoseAllState.itensProcessados,

    itens_com_1000:
      itensCom1000.length,

    itens_com_500_ou_mais:
      itensCom500.length,

    top_20_itens:
      ordenados.slice(0, 20),

    itens_no_limite:
      itensCom1000,

    erros:
      diagnoseAllState.erros.length,

    detalhes_erros:
      diagnoseAllState.erros.slice(0, 20),

    iniciado_em:
      diagnoseAllState.iniciadoEm,

    finalizado_em:
      diagnoseAllState.finalizadoEm
  });
});

app.get("/item-status-diagnostic", async (req, res) => {
  try {
    if (!authState.accessToken || !authState.shopId) {
      return res.status(401).json({
        ok: false,
        message: "Loja ainda não autorizada nesta execução."
      });
    }

    if (authState.expiresAt <= Date.now()) {
      return res.status(401).json({
        ok: false,
        message: "Access token expirado."
      });
    }

    const path = "/api/v2/product/get_item_list";

    const statusParaTestar = [
      "NORMAL",
      "BANNED",
      "DELETED",
      "UNLIST"
    ];

    const resultados = [];

    for (const status of statusParaTestar) {
      let offset = 0;
      const pageSize = 100;
      let hasNextPage = true;

      const itens = [];

      try {
        while (hasNextPage) {
          const timestamp = Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            path,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          const url =
            `https://partner.shopeemobile.com${path}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&offset=${offset}` +
            `&page_size=${pageSize}` +
            `&item_status=${status}`;

          const response = await fetch(url);
          const data = await response.json();

          if (data.error) {
            resultados.push({
              status,
              suportado: false,
              erro: data
            });

            break;
          }

          const lista = data.response?.item || [];

          itens.push(...lista);

          hasNextPage =
            data.response?.has_next_page === true;

          offset =
            data.response?.next_offset ??
            offset + lista.length;

          if (lista.length === 0) {
            break;
          }
        }

        if (
          !resultados.some(
            resultado =>
              resultado.status === status &&
              resultado.suportado === false
          )
        ) {
          resultados.push({
            status,
            suportado: true,
            total_itens: itens.length,
            amostra_item_ids: itens
              .slice(0, 10)
              .map(item => item.item_id)
          });
        }

      } catch (error) {
        resultados.push({
          status,
          suportado: false,
          erro: error.message
        });
      }
    }

    const totalEncontrado = resultados
      .filter(resultado => resultado.suportado)
      .reduce(
        (total, resultado) =>
          total + (resultado.total_itens || 0),
        0
      );

    return res.json({
      ok: true,
      total_itens_encontrados:
        totalEncontrado,
      resultados
    });

  } catch (error) {
    console.error(
      "Erro no diagnóstico de status:"
    );

    console.error(error);

    return res.status(500).json({
      ok: false,
      message: error.message
    });
  }
});

async function executarScanCompletoAvaliacoes() {
  try {
    fullReviewScanState = {
      running: true,
      concluido: false,

      totalItens: 0,
      itensProcessados: 0,

      itensPorStatus: {
        NORMAL: 0,
        DELETED: 0,
        UNLIST: 0
      },

      itensProcessadosPorStatus: {
        NORMAL: 0,
        DELETED: 0,
        UNLIST: 0
      },

      comentarios: new Map(),

      erros: [],

      iniciadoEm: new Date().toISOString(),
      finalizadoEm: null
    };

    console.log(
      "Iniciando scanner completo de avaliações..."
    );

    // =====================================
    // 1. BUSCAR ITENS DE TODOS OS STATUS
    // =====================================

    const itemListPath =
      "/api/v2/product/get_item_list";

    const statusLista = [
      "NORMAL",
      "DELETED",
      "UNLIST"
    ];

    const todosItens = [];

    for (const status of statusLista) {
      let offset = 0;
      const pageSize = 100;
      let hasNextPage = true;

      while (hasNextPage) {
        const timestamp =
          Math.floor(Date.now() / 1000);

        const sign = gerarAssinatura(
          itemListPath,
          timestamp,
          authState.accessToken,
          authState.shopId
        );

        const url =
          `https://partner.shopeemobile.com${itemListPath}` +
          `?partner_id=${PARTNER_ID}` +
          `&timestamp=${timestamp}` +
          `&access_token=${authState.accessToken}` +
          `&shop_id=${authState.shopId}` +
          `&sign=${sign}` +
          `&offset=${offset}` +
          `&page_size=${pageSize}` +
          `&item_status=${status}`;

        const response = await fetch(url);
        const data = await response.json();

        if (data.error) {
          throw new Error(
            `Erro get_item_list ${status}: ${JSON.stringify(data)}`
          );
        }

        const lista =
          data.response?.item || [];

        for (const item of lista) {
          todosItens.push({
            item_id: Number(item.item_id),
            status
          });
        }

        fullReviewScanState
          .itensPorStatus[status] +=
          lista.length;

        hasNextPage =
          data.response?.has_next_page === true;

        offset =
          data.response?.next_offset ??
          offset + lista.length;

        if (lista.length === 0) {
          break;
        }
      }
    }

    // =====================================
    // 2. REMOVER ITEM_ID DUPLICADO
    // =====================================

    const mapaItens = new Map();

    for (const item of todosItens) {
      mapaItens.set(
        String(item.item_id),
        item
      );
    }

    const itensUnicos =
      Array.from(mapaItens.values());

    fullReviewScanState.totalItens =
      itensUnicos.length;

    console.log(
      `Itens únicos para processar: ${itensUnicos.length}`
    );

    console.log(
      "Itens por status:",
      fullReviewScanState.itensPorStatus
    );

    // =====================================
    // 3. BUSCAR AVALIAÇÕES ITEM POR ITEM
    // =====================================

    const commentPath =
      "/api/v2/product/get_comment";

    for (const item of itensUnicos) {
      const itemId =
        Number(item.item_id);

      const status =
        item.status;

      let cursor = "";
      let more = true;
      let totalItem = 0;

      try {
        while (more) {
          const timestamp =
            Math.floor(Date.now() / 1000);

          const sign = gerarAssinatura(
            commentPath,
            timestamp,
            authState.accessToken,
            authState.shopId
          );

          let url =
            `https://partner.shopeemobile.com${commentPath}` +
            `?partner_id=${PARTNER_ID}` +
            `&timestamp=${timestamp}` +
            `&access_token=${authState.accessToken}` +
            `&shop_id=${authState.shopId}` +
            `&sign=${sign}` +
            `&page_size=100` +
            `&item_id=${itemId}`;

          if (cursor) {
            url +=
              `&cursor=${encodeURIComponent(cursor)}`;
          }

          const response =
            await fetch(url);

          const data =
            await response.json();

          if (data.error) {
            throw new Error(
              JSON.stringify(data)
            );
          }

          const lista =
            data.response
              ?.item_comment_list || [];

          for (const avaliacao of lista) {
            fullReviewScanState
              .comentarios
              .set(
                String(
                  avaliacao.comment_id
                ),
                {
                  ...avaliacao,
                  item_status: status
                }
              );
          }

          totalItem +=
            lista.length;

          more =
            data.response?.more === true;

          cursor =
            data.response?.next_cursor || "";

          if (more && !cursor) {
            break;
          }

          // teto conhecido do endpoint
          if (totalItem >= 1000) {
            break;
          }
        }

      } catch (error) {
        fullReviewScanState.erros.push({
          item_id: itemId,
          status,
          erro: error.message
        });
      }

      fullReviewScanState
        .itensProcessados++;

      if (
        fullReviewScanState
          .itensProcessadosPorStatus[status]
        !== undefined
      ) {
        fullReviewScanState
          .itensProcessadosPorStatus[status]++;
      }

      if (
        fullReviewScanState
          .itensProcessados %
          50 ===
        0
      ) {
        console.log(
          `Scanner: ${fullReviewScanState.itensProcessados}/${fullReviewScanState.totalItens}`
        );
      }

      // pequena pausa entre anúncios
      await new Promise(resolve =>
        setTimeout(resolve, 150)
      );
    }

    fullReviewScanState.running =
      false;

    fullReviewScanState.concluido =
      true;

    fullReviewScanState.finalizadoEm =
      new Date().toISOString();

    console.log(
      "Scanner completo finalizado."
    );

  } catch (error) {
    console.error(
      "Erro geral no scanner completo:"
    );

    console.error(error);

    fullReviewScanState.running =
      false;

    fullReviewScanState.concluido =
      false;

    fullReviewScanState.erros.push({
      geral: true,
      erro: error.message
    });
  }
}

app.get("/scan-all-reviews", (req, res) => {
  if (
    !authState.accessToken ||
    !authState.shopId
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Loja ainda não autorizada nesta execução."
    });
  }

  if (
    authState.expiresAt <= Date.now()
  ) {
    return res.status(401).json({
      ok: false,
      message:
        "Access token expirado."
    });
  }

  if (fullReviewScanState.running) {
    return res.json({
      ok: true,
      message:
        "Scanner já está em execução.",
      itens_processados:
        fullReviewScanState.itensProcessados,
      total_itens:
        fullReviewScanState.totalItens
    });
  }

  executarScanCompletoAvaliacoes();

  return res.json({
    ok: true,
    message:
      "Scanner completo iniciado.",
    status_url:
      "/scan-all-status"
  });
});

app.get("/scan-all-status", (req, res) => {
  const avaliacoes =
    Array.from(
      fullReviewScanState
        .comentarios
        .values()
    );

  const pendentes =
    avaliacoes.filter(
      avaliacao =>
        !avaliacao.comment_reply
    );

  const porEstrela = {
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0
  };

  const pendentesPorStatus = {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  };

  let semComentario = 0;
  let comComentario = 0;

  for (const avaliacao of pendentes) {
    const estrela =
      Number(avaliacao.rating_star);

    if (
      porEstrela[estrela] !== undefined
    ) {
      porEstrela[estrela]++;
    }

    const status =
      avaliacao.item_status;

    if (
      pendentesPorStatus[status]
      !== undefined
    ) {
      pendentesPorStatus[status]++;
    }

    if (
      !avaliacao.comment ||
      avaliacao.comment.trim() === ""
    ) {
      semComentario++;
    } else {
      comComentario++;
    }
  }

  let progresso = 0;

  if (
    fullReviewScanState.totalItens > 0
  ) {
    progresso =
      (
        fullReviewScanState
          .itensProcessados /
        fullReviewScanState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      fullReviewScanState.running,

    concluido:
      fullReviewScanState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      fullReviewScanState.totalItens,

    itens_processados:
      fullReviewScanState
        .itensProcessados,

    itens_por_status:
      fullReviewScanState
        .itensPorStatus,

    itens_processados_por_status:
      fullReviewScanState
        .itensProcessadosPorStatus,

    avaliacoes_unicas:
      avaliacoes.length,

    total_pendentes:
      pendentes.length,

    pendentes_sem_comentario:
      semComentario,

    pendentes_com_comentario:
      comComentario,

    pendentes_por_estrela:
      porEstrela,

    pendentes_por_status:
      pendentesPorStatus,

    erros:
      fullReviewScanState
        .erros.length,

    detalhes_erros:
      fullReviewScanState
        .erros
        .slice(0, 20),

    iniciado_em:
      fullReviewScanState
        .iniciadoEm,

    finalizado_em:
      fullReviewScanState
        .finalizadoEm
  });
});

app.get("/scan-all-status", (req, res) => {
  const avaliacoes =
    Array.from(
      fullReviewScanState
        .comentarios
        .values()
    );

  const pendentes =
    avaliacoes.filter(
      avaliacao =>
        !avaliacao.comment_reply
    );

  const porEstrela = {
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0
  };

  const pendentesPorStatus = {
    NORMAL: 0,
    DELETED: 0,
    UNLIST: 0
  };

  let semComentario = 0;
  let comComentario = 0;

  for (const avaliacao of pendentes) {
    const estrela =
      Number(avaliacao.rating_star);

    if (
      porEstrela[estrela] !== undefined
    ) {
      porEstrela[estrela]++;
    }

    const status =
      avaliacao.item_status;

    if (
      pendentesPorStatus[status]
      !== undefined
    ) {
      pendentesPorStatus[status]++;
    }

    if (
      !avaliacao.comment ||
      avaliacao.comment.trim() === ""
    ) {
      semComentario++;
    } else {
      comComentario++;
    }
  }

  let progresso = 0;

  if (
    fullReviewScanState.totalItens > 0
  ) {
    progresso =
      (
        fullReviewScanState
          .itensProcessados /
        fullReviewScanState.totalItens *
        100
      ).toFixed(1);
  }

  return res.json({
    ok: true,

    running:
      fullReviewScanState.running,

    concluido:
      fullReviewScanState.concluido,

    progresso_percentual:
      Number(progresso),

    total_itens:
      fullReviewScanState.totalItens,

    itens_processados:
      fullReviewScanState
        .itensProcessados,

    itens_por_status:
      fullReviewScanState
        .itensPorStatus,

    itens_processados_por_status:
      fullReviewScanState
        .itensProcessadosPorStatus,

    avaliacoes_unicas:
      avaliacoes.length,

    total_pendentes:
      pendentes.length,

    pendentes_sem_comentario:
      semComentario,

    pendentes_com_comentario:
      comComentario,

    pendentes_por_estrela:
      porEstrela,

    pendentes_por_status:
      pendentesPorStatus,

    erros:
      fullReviewScanState
        .erros.length,

    detalhes_erros:
      fullReviewScanState
        .erros
        .slice(0, 20),

    iniciado_em:
      fullReviewScanState
        .iniciadoEm,

    finalizado_em:
      fullReviewScanState
        .finalizadoEm
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
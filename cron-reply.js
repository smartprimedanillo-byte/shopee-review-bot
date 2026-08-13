const URL = process.env.REPLY_BATCH_URL;
const SECRET = process.env.REPLY_CRON_SECRET;

async function executar() {
  if (!URL) {
    throw new Error(
      "REPLY_BATCH_URL não configurada."
    );
  }

  if (!SECRET) {
    throw new Error(
      "REPLY_CRON_SECRET não configurada."
    );
  }

  console.log(
    `[CRON] Iniciando chamada em ${new Date().toISOString()}`
  );

  const response = await fetch(URL, {
    method: "POST",

    headers: {
      "x-cron-secret": SECRET
    }
  });

  const texto =
    await response.text();

  let data;

  try {
    data = JSON.parse(texto);
  } catch {
    data = {
      resposta: texto
    };
  }

  // Lote já em execução.
  // Não consideramos falha do Cron.
  if (response.status === 409) {
    console.log(
      "[CRON] Lote já estava em execução."
    );

    process.exit(0);
  }

  // Limite diário atingido.
  // Também não é erro operacional.
  if (response.status === 429) {
    console.log(
      "[CRON] Limite diário atingido."
    );

    console.log({
      limite_diario:
        data.limite_diario,

      respondidas_hoje:
        data.respondidas_hoje,

      restante_hoje:
        data.restante_hoje
    });

    process.exit(0);
  }

  if (!response.ok) {
    console.error(
      "[CRON] Erro HTTP:",
      response.status
    );

    console.error(data);

    process.exit(1);
  }

  console.log(
    "[CRON] Lote concluído:",
    {
      total_processado:
        data.total_processado,

      enviadas:
        data.enviadas,

      erros:
        data.erros,

      ignoradas:
        data.ignoradas
    }
  );

  process.exit(0);
}

executar().catch(error => {
  console.error(
    "[CRON] Falha:",
    error.message
  );

  process.exit(1);
});
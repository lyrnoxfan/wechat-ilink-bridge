import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { readFile, stat, unlink, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import os from "node:os";
import { WxbError } from "./errors.js";
import { generateClientId, IlinkClient } from "./ilink-client.js";
import { outgoingItemTypes, protocolDefaults, uploadMediaTypes } from "./protocol-constants.js";
import { resolveSendAccount, resolveTargetUserOrAlias } from "./send-text.js";
import { sanitizeAttachmentFileName } from "./media-download.js";
import { withOptionalTyping } from "./typing.js";
import { resolveContextToken } from "../state/context-token-store.js";
import { appendMessageHistory } from "../state/message-history.js";
import { withAccountLock } from "../state/lock.js";

const mediaTypeByKind = Object.freeze({
  image: uploadMediaTypes.image,
  file: uploadMediaTypes.file,
  voice: uploadMediaTypes.voice
});

const mimeByExtension = Object.freeze({
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".pdf": "application/pdf",
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".json": "application/json",
  ".csv": "text/csv",
  ".zip": "application/zip",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".m4a": "audio/mp4",
  ".amr": "audio/amr",
  ".ogg": "audio/ogg",
  ".silk": "audio/silk"
});

function inferMimeType(filePath) {
  return mimeByExtension[path.extname(filePath).toLowerCase()];
}

const execFileAsync = promisify(execFile);
const SILK_ENCODER = "/home/hatch/workspace/silk-tools/encoder";

async function getAudioDurationMs(filePath) {
  try {
    const { stdout } = await execFileAsync("ffprobe", [
      "-v", "error", "-show_entries", "format=duration",
      "-of", "default=noprint_wrappers=1:nokey=1", filePath
    ]);
    const secs = parseFloat(stdout.trim());
    return Number.isFinite(secs) ? Math.round(secs * 1000) : 0;
  } catch {
    return 0;
  }
}

async function convertToSilk(inputPath) {
  const tmpPcm = path.join(os.tmpdir(), `silk-${Date.now()}-${Math.random().toString(36).slice(2)}.pcm`);
  const tmpSilk = path.join(os.tmpdir(), `silk-${Date.now()}-${Math.random().toString(36).slice(2)}.silk`);
  try {
    await execFileAsync("ffmpeg", ["-y", "-loglevel", "error", "-i", inputPath, "-ar", "24000", "-ac", "1", "-f", "s16le", tmpPcm]);
    await execFileAsync(SILK_ENCODER, [tmpPcm, tmpSilk, "-rate", "24000"]);
    const bytes = await readFile(tmpSilk);
    return bytes;
  } finally {
    await unlink(tmpPcm).catch(() => {});
    await unlink(tmpSilk).catch(() => {});
  }
}

function isSilkFile(filePath, bytes) {
  if (path.extname(filePath).toLowerCase() === ".silk") return true;
  return bytes.length > 10 && bytes.subarray(0, 10).toString("latin1").includes("SILK");
}

function md5Hex(buffer) {
  return createHash("md5").update(buffer).digest("hex");
}

function encryptAes128Ecb(buffer, key) {
  const cipher = createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function resolveUploadParam(response = {}) {
  return response.upload_param
    ?? response.uploadParam
    ?? response.data?.upload_param
    ?? response.data?.uploadParam;
}

function buildCdnUploadUrl({ cdnBaseUrl, uploadParam, fileKey }) {
  const url = new URL("upload", cdnBaseUrl.endsWith("/") ? cdnBaseUrl : `${cdnBaseUrl}/`);
  url.searchParams.set("encrypted_query_param", uploadParam);
  url.searchParams.set("filekey", fileKey);
  return url.toString();
}

function resolveUploadUrl(response = {}, { cdnBaseUrl, fileKey } = {}) {
  const directUrl = response.upload_url
    ?? response.uploadUrl
    ?? response.url
    ?? response.cdn_upload_url
    ?? response.cdnUploadUrl
    ?? response.upload_info?.url
    ?? response.uploadInfo?.url
    ?? response.data?.upload_url
    ?? response.data?.uploadUrl
    ?? response.data?.url
    ?? response.data?.upload_info?.url
    ?? response.data?.uploadInfo?.url;
  if (directUrl) {
    return directUrl;
  }

  const uploadParam = resolveUploadParam(response);
  if (uploadParam) {
    return buildCdnUploadUrl({
      cdnBaseUrl: cdnBaseUrl ?? protocolDefaults.cdnBaseUrl,
      uploadParam,
      fileKey
    });
  }

  return undefined;
}

function resolveDownloadParam(response = {}) {
  return response.headers?.["x-encrypted-param"]
    ?? response.headers?.["X-Encrypted-Param"]
    ?? response.body?.encrypt_query_param
    ?? response.body?.encryptQueryParam
    ?? response.body?.download_param
    ?? response.body?.downloadParam
    ?? response.body?.data?.encrypt_query_param
    ?? response.body?.data?.encryptQueryParam
    ?? response.body?.data?.download_param
    ?? response.body?.data?.downloadParam;
}

function resolveUploadConfigDownloadParam(response = {}) {
  return response.upload_url
    ? undefined
    : response.encrypt_query_param
      ?? response.encryptQueryParam
      ?? response.download_param
      ?? response.downloadParam
      ?? response.data?.encrypt_query_param
      ?? response.data?.encryptQueryParam
      ?? response.data?.download_param
      ?? response.data?.downloadParam;
}

function encodeMediaAesKey(aesKeyHex) {
  return Buffer.from(aesKeyHex).toString("base64");
}

async function inspectLocalMedia(filePath, kind, config = {}) {
  const absolutePath = path.resolve(filePath ?? "");
  let info;

  try {
    info = await stat(absolutePath);
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new WxbError("MEDIA_FILE_NOT_FOUND", "Media file does not exist.", {
        retryable: false,
        details: { path: absolutePath }
      });
    }
    throw error;
  }

  if (!info.isFile()) {
    throw new WxbError("MEDIA_PATH_NOT_FILE", "Media path must point to a regular file.", {
      retryable: false,
      details: { path: absolutePath }
    });
  }

  const maxUploadBytes = config.maxUploadBytes ?? 25 * 1024 * 1024;
  if (info.size > maxUploadBytes) {
    throw new WxbError("MEDIA_FILE_TOO_LARGE", "Media file exceeds the configured upload size limit.", {
      retryable: false,
      details: {
        path: absolutePath,
        bytes: info.size,
        maxUploadBytes
      }
    });
  }

  const mimeType = inferMimeType(absolutePath);
  if (!mimeType || (kind === "image" && !mimeType.startsWith("image/"))) {
    throw new WxbError("MEDIA_TYPE_UNSUPPORTED", "Media MIME type could not be inferred or is not supported for this send mode.", {
      retryable: false,
      details: {
        path: absolutePath,
        kind,
        extension: path.extname(absolutePath).toLowerCase() || undefined
      }
    });
  }

  const bytes = await readFile(absolutePath);

  // Voice messages must be SILK format for WeChat; convert if needed
  let finalBytes = bytes;
  let finalFileName = sanitizeAttachmentFileName(path.basename(absolutePath));
  let durationMs = 0;
  if (kind === "voice") {
    durationMs = await getAudioDurationMs(absolutePath);
    if (!isSilkFile(absolutePath, bytes)) {
      finalBytes = await convertToSilk(absolutePath);
      finalFileName = finalFileName.replace(/\.[^.]+$/, "") + ".silk";
    }
  }

  return {
    path: absolutePath,
    bytes: finalBytes,
    rawSize: finalBytes.length,
    rawMd5: md5Hex(finalBytes),
    fileName: finalFileName,
    mimeType: kind === "voice" ? "audio/silk" : mimeType,
    durationMs
  };
}

function buildUploadRequest({ fileKey, mediaType, targetUserId, local, encryptedBytes, aesKeyHex }) {
  return {
    filekey: fileKey,
    media_type: mediaType,
    to_user_id: targetUserId,
    rawsize: local.rawSize,
    rawfilemd5: local.rawMd5,
    filesize: encryptedBytes.length,
    thumb_rawsize: 0,
    thumb_rawfilemd5: "",
    thumb_filesize: 0,
    no_need_thumb: true,
    aeskey: aesKeyHex
  };
}

function buildCdnMedia({ downloadParam, aesKeyHex }) {
  return {
    encrypt_query_param: downloadParam,
    aes_key: encodeMediaAesKey(aesKeyHex),
    encrypt_type: 1
  };
}

function buildMediaItem({ kind, local, encryptedBytes, aesKeyHex, downloadParam }) {
  if (kind === "image") {
    return {
      type: outgoingItemTypes.image,
      image_item: {
        media: {
          ...buildCdnMedia({ downloadParam, aesKeyHex })
        },
        mid_size: encryptedBytes.length
      }
    };
  }

  if (kind === "voice") {
    return {
      type: outgoingItemTypes.voice,
      voice_item: {
        media: {
          ...buildCdnMedia({ downloadParam, aesKeyHex })
        },
        playtime: local.durationMs ?? 0
      }
    };
  }

  return {
    type: outgoingItemTypes.file,
    file_item: {
      media: {
        ...buildCdnMedia({ downloadParam, aesKeyHex })
      },
      file_name: local.fileName,
      md5: local.rawMd5,
      len: String(local.rawSize)
    }
  };
}

export async function sendMedia(options = {}) {
  const {
    stateDir,
    accountId,
    userId,
    filePath,
    kind = "file",
    config = {},
    client: providedClient,
    timeoutMs = config.fetchTimeoutMs,
    typing = false
  } = options;

  if (!stateDir) {
    throw new TypeError("stateDir is required");
  }

  if (!["file", "image", "voice"].includes(kind)) {
    throw new WxbError("MEDIA_KIND_UNSUPPORTED", "Only file, image and voice sends are supported.", {
      retryable: false,
      details: { kind }
    });
  }

  const targetUserId = await resolveTargetUserOrAlias(stateDir, {
    userId,
    alias: options.alias
  });
  const account = await resolveSendAccount(stateDir, accountId);
  const local = await inspectLocalMedia(filePath, kind, config);
  const client = providedClient ?? new IlinkClient({
    baseUrl: account.baseUrl ?? config.baseUrl,
    channelVersion: config.channelVersion
  });

  return withAccountLock(stateDir, account.accountId, async () => {
    const contextToken = await resolveContextToken(stateDir, account.accountId, targetUserId);
    if (!contextToken) {
      throw new WxbError("NO_CONTEXT_TOKEN", "No context token is cached for this user; fetch an inbound message first.", {
        retryable: false,
        details: {
          accountId: account.accountId,
          userId: targetUserId
        }
      });
    }

    return withOptionalTyping({
      enabled: typing,
      client,
      token: account.token,
      stateDir,
      accountId: account.accountId,
      userId: targetUserId,
      contextToken,
      timeoutMs
    }, async (activeContextToken) => {
      const clientId = generateClientId();
      const aesKey = randomBytes(16);
      const aesKeyHex = aesKey.toString("hex");
      const encryptedBytes = encryptAes128Ecb(local.bytes, aesKey);
      const fileKey = randomBytes(16).toString("hex");
      const uploadRequest = buildUploadRequest({
        fileKey,
        mediaType: mediaTypeByKind[kind],
        targetUserId,
        local,
        encryptedBytes,
        aesKeyHex
      });
      const uploadConfig = await client.getUploadUrl({
        token: account.token,
        upload: uploadRequest,
        timeoutMs
      });
      const uploadUrl = resolveUploadUrl(uploadConfig, {
        cdnBaseUrl: config.cdnBaseUrl,
        fileKey
      });

      if (!uploadUrl) {
        throw new WxbError("MEDIA_UPLOAD_URL_MISSING", "iLink did not return a media upload URL.", {
          retryable: false,
          details: { kind, fileName: local.fileName }
        });
      }

      let uploadResponse;
      try {
        uploadResponse = await client.uploadBytes({
          uploadUrl,
          bytes: encryptedBytes,
          contentType: "application/octet-stream",
          timeoutMs
        });
      } catch (error) {
        if (error instanceof WxbError) {
          throw error;
        }
        throw new WxbError("MEDIA_UPLOAD_FAILED", "Media upload failed.", {
          retryable: true,
          details: { cause: error?.message ?? String(error) }
        });
      }

      const downloadParam = resolveDownloadParam(uploadResponse) ?? resolveUploadConfigDownloadParam(uploadConfig);
      if (!downloadParam) {
        throw new WxbError("MEDIA_UPLOAD_PARAM_MISSING", "CDN upload did not return an encrypted media download parameter.", {
          retryable: false,
          details: { kind, fileName: local.fileName }
        });
      }

      const item = buildMediaItem({
        kind,
        local,
        encryptedBytes,
        aesKeyHex,
        downloadParam
      });

      try {
        await client.sendMediaMessage({
          token: account.token,
          toUserId: targetUserId,
          item,
          contextToken: activeContextToken,
          clientId,
          timeoutMs
        });
      } catch (error) {
        if (!(error instanceof WxbError)) {
          throw error;
        }
        throw new WxbError(error.code, error.message, {
          retryable: error.retryable,
          status: error.status,
          details: {
            ...(error.details ?? {}),
            uploaded: true,
            clientId,
            kind,
            fileName: local.fileName
          }
        });
      }

      const historyEntry = {
        id: clientId,
        direction: "outgoing",
        fromUserId: account.ownerUserId,
        toUserId: targetUserId,
        timestamp: Math.floor(Date.now() / 1000),
        type: kind,
        contextToken: activeContextToken,
        attachment: {
          kind,
          fileKey,
          fileName: local.fileName,
          mimeType: local.mimeType,
          bytes: local.rawSize,
          encrypted: true,
          uploaded: true
        }
      };

      try {
        await appendMessageHistory(stateDir, account.accountId, historyEntry);
      } catch (error) {
        throw new WxbError("OUTGOING_HISTORY_WRITE_FAILED", "Media was sent but local outgoing history could not be written.", {
          retryable: false,
          details: {
            delivered: true,
            sentCount: 1,
            clientId,
            cause: error?.message ?? String(error)
          }
        });
      }

      return {
        accountId: account.accountId,
        toUserId: targetUserId,
        kind,
        clientId,
        fileName: local.fileName,
        mimeType: local.mimeType,
        bytes: local.rawSize,
        encryptedBytes: encryptedBytes.length,
        uploaded: true,
        sent: true
      };
    });
  });
}

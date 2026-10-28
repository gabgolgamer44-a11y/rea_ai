import { PacketCaptureService } from "../application/captures/PacketCaptureService.js";
import {
  TsharkCaptureProvider,
  tsharkHostSupported,
  tsharkOfflineCaptureSupported,
  tsharkLiveCaptureSupported,
} from "../captures/TsharkCaptureProvider.js";

export {
  tsharkHostSupported,
  tsharkOfflineCaptureSupported,
  tsharkLiveCaptureSupported,
};

export const createPacketCaptureService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): PacketCaptureService =>
  new PacketCaptureService(new TsharkCaptureProvider(environment));

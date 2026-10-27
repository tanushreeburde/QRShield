import logging
import cv2
import numpy as np
from typing import Optional, Tuple

logger = logging.getLogger("qrshield.qr_decoder")

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except Exception as e:
    logger.warning("pyzbar not available: %s", e)
    HAS_PYZBAR = False


class MultiEngineQRDecoder:
    """
    QR decoder optimized for uploaded screenshots and photographs.

    Strategy:
    1. Decode original image with pyzbar.
    2. Decode original image with OpenCV.
    3. Try grayscale.
    4. Try resized image when necessary.
    5. Try a small number of thresholded variants.
    
    The decoder deliberately avoids running every QR engine against
    every preprocessing variant because that can make image uploads
    unnecessarily slow.
    """

    def __init__(self):
        self.detector_standard = cv2.QRCodeDetector()

        try:
            self.detector_aruco = cv2.QRCodeDetectorAruco()
        except Exception:
            self.detector_aruco = None

    def _try_pyzbar(self, img: np.ndarray) -> Optional[str]:
        """Try ZBar/pyzbar once on an image."""
        if not HAS_PYZBAR:
            return None

        try:
            decoded_objects = pyzbar_decode(img)

            for obj in decoded_objects:
                data = obj.data.decode(
                    "utf-8",
                    errors="replace"
                ).strip()

                if data:
                    return data

        except Exception as e:
            logger.debug("pyzbar decode failed: %s", e)

        return None

    def _try_opencv(self, img: np.ndarray) -> Optional[str]:
        """Try OpenCV QR detection."""
        
        # Standard OpenCV detector first.
        try:
            data, points, _ = self.detector_standard.detectAndDecode(img)

            if data and data.strip():
                return data.strip()

        except Exception as e:
            logger.debug("OpenCV QRCodeDetector failed: %s", e)

        # ArUco-based detector as a fallback.
        if self.detector_aruco is not None:
            try:
                data, points, _ = self.detector_aruco.detectAndDecode(img)

                if data and data.strip():
                    return data.strip()

            except Exception as e:
                logger.debug("OpenCV QRCodeDetectorAruco failed: %s", e)

        return None

    def _try_all_fast(self, img: np.ndarray) -> Optional[str]:
        """
        Run the fast engines once on the supplied image.
        """
        result = self._try_pyzbar(img)

        if result:
            return result

        return self._try_opencv(img)

    def decode_bytes(
        self,
        image_bytes: bytes
    ) -> Tuple[Optional[str], Optional[str]]:

        if not image_bytes:
            return None, "Empty image data provided."

        try:
            # ---------------------------------------------------------
            # 1. Decode uploaded file
            # ---------------------------------------------------------
            nparr = np.frombuffer(image_bytes, np.uint8)

            img = cv2.imdecode(
                nparr,
                cv2.IMREAD_COLOR
            )

            if img is None:
                return (
                    None,
                    "Failed to decode image file. "
                    "Unsupported format or corrupt image."
                )

            original_h, original_w = img.shape[:2]

            logger.info(
                "QR image received: %sx%s, %.2f MB",
                original_w,
                original_h,
                len(image_bytes) / (1024 * 1024),
            )

            # ---------------------------------------------------------
            # 2. Limit extremely large images
            # ---------------------------------------------------------
            max_dim = max(original_h, original_w)

            if max_dim > 1800:
                scale = 1800.0 / max_dim

                new_w = max(1, int(original_w * scale))
                new_h = max(1, int(original_h * scale))

                img = cv2.resize(
                    img,
                    (new_w, new_h),
                    interpolation=cv2.INTER_AREA,
                )

            # ---------------------------------------------------------
            # PASS 1: Original image
            # Works well for normal QR photos and screenshots.
            # ---------------------------------------------------------
            result = self._try_all_fast(img)

            if result:
                logger.info("QR decoded from original image.")
                return result, None

            # ---------------------------------------------------------
            # PASS 2: Grayscale
            # Useful for screenshots and low-color images.
            # ---------------------------------------------------------
            gray = cv2.cvtColor(
                img,
                cv2.COLOR_BGR2GRAY
            )

            result = self._try_all_fast(gray)

            if result:
                logger.info("QR decoded from grayscale image.")
                return result, None

            # ---------------------------------------------------------
            # PASS 3: Upscale small images
            # Small screenshots/photos can benefit from enlargement.
            # ---------------------------------------------------------
            h, w = gray.shape[:2]

            if max(h, w) < 800:
                scale = 2.0

                enlarged = cv2.resize(
                    gray,
                    None,
                    fx=scale,
                    fy=scale,
                    interpolation=cv2.INTER_CUBIC,
                )

                result = self._try_all_fast(enlarged)

                if result:
                    logger.info("QR decoded from enlarged image.")
                    return result, None

            # ---------------------------------------------------------
            # PASS 4: OTSU threshold
            # Useful for clean screenshots.
            # ---------------------------------------------------------
            _, otsu = cv2.threshold(
                gray,
                0,
                255,
                cv2.THRESH_BINARY + cv2.THRESH_OTSU,
            )

            result = self._try_all_fast(otsu)

            if result:
                logger.info("QR decoded using OTSU threshold.")
                return result, None

            # ---------------------------------------------------------
            # PASS 5: Adaptive threshold
            # Useful for photographs with uneven lighting.
            # ---------------------------------------------------------
            adaptive = cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                31,
                5,
            )

            result = self._try_all_fast(adaptive)

            if result:
                logger.info(
                    "QR decoded using adaptive threshold."
                )
                return result, None

            # ---------------------------------------------------------
            # Nothing worked
            # ---------------------------------------------------------
            return (
                None,
                "No QR code could be detected. "
                "Please ensure the QR code is clearly visible, "
                "large enough, and in focus."
            )

        except Exception as e:
            logger.exception(
                "QR decoding exception"
            )

            return (
                None,
                f"QR decoding error: {str(e)}"
            )


qr_decoder = MultiEngineQRDecoder()
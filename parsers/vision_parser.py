"""
Vision Parser Module using Granite-Vision

Provides image and visual content analysis for fraud detection.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import structlog
from PIL import Image
from transformers import AutoProcessor, AutoModelForVision2Seq
import torch
import re

logger = structlog.get_logger(__name__)


class VisionParser:
    """
    Vision parser using Granite-Vision models for image analysis.

    Features:
    - Image content extraction
    - Visual fraud detection
    - Screenshot analysis
    - OCR capabilities
    - Phishing page detection
    """

    def __init__(
        self,
        model_name: str = "ibm-granite/granite-vision-base",
        device: Optional[str] = None
    ):
        """
        Initialize vision parser.

        Args:
            model_name: Hugging Face model name
            device: Device to use (cuda/cpu), auto-detected if None
        """
        self.model_name = model_name

        # Auto-detect device
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.processor = None
        self.model = None
        self._initialized = False

        logger.info("vision_parser_created", model=model_name, device=self.device)

    def _lazy_load(self):
        """Lazy load model and processor."""
        if not self._initialized:
            try:
                logger.info("vision_model_loading", model=self.model_name)

                # Note: This is a placeholder. Granite Vision may require specific model loading.
                # Using a generic vision model approach compatible with transformers
                self.processor = AutoProcessor.from_pretrained(self.model_name)
                self.model = AutoModelForVision2Seq.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float16 if self.device == "cuda" else torch.float32
                ).to(self.device)

                self._initialized = True
                logger.info("vision_model_loaded", model=self.model_name)

            except Exception as e:
                logger.error("vision_model_load_failed", error=str(e))
                raise

    def parse_image(
        self,
        image_path: str,
        prompt: str = "Describe this image in detail, focusing on any suspicious or fraudulent content."
    ) -> Dict[str, Any]:
        """
        Parse an image and extract content.

        Args:
            image_path: Path to image file
            prompt: Analysis prompt

        Returns:
            Parsed image content dictionary
        """
        try:
            self._lazy_load()

            path = Path(image_path)
            if not path.exists():
                raise FileNotFoundError(f"Image not found: {image_path}")

            # Load image
            image = Image.open(image_path).convert("RGB")

            # Process image
            inputs = self.processor(
                text=prompt,
                images=image,
                return_tensors="pt"
            ).to(self.device)

            # Generate description
            with torch.no_grad():
                outputs = self.model.generate(**inputs, max_new_tokens=512)
                description = self.processor.batch_decode(outputs, skip_special_tokens=True)[0]

            # Basic image info
            content = {
                "image_path": image_path,
                "image_name": path.name,
                "image_size": image.size,
                "image_mode": image.mode,
                "description": description,
                "success": True,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Detect fraud indicators in description
            content["fraud_indicators"] = self._detect_fraud_indicators(description)

            # Extract text from image using OCR (if available)
            try:
                import pytesseract
                ocr_text = pytesseract.image_to_string(image)
                content["ocr_text"] = ocr_text
                content["ocr_iocs"] = self._extract_iocs_from_text(ocr_text)
            except ImportError:
                logger.debug("pytesseract_not_available")
                content["ocr_text"] = None
            except Exception as e:
                logger.warning("ocr_extraction_failed", error=str(e))
                content["ocr_text"] = None

            logger.info("image_parsed", image=image_path, fraud_indicators=len(content["fraud_indicators"]))
            return content

        except Exception as e:
            logger.error("image_parse_failed", image=image_path, error=str(e))
            return {
                "image_path": image_path,
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def analyze_screenshot(self, image_path: str) -> Dict[str, Any]:
        """
        Analyze a screenshot for phishing or fraud indicators.

        Args:
            image_path: Path to screenshot

        Returns:
            Analysis results
        """
        prompt = """Analyze this screenshot for potential phishing or fraud indicators:
        - Suspicious login pages
        - Fake security warnings
        - Misleading buttons or forms
        - Brand impersonation
        - Suspicious URLs visible
        - Urgent or threatening messages
        Provide detailed findings."""

        result = self.parse_image(image_path, prompt)

        # Additional screenshot-specific analysis
        if result.get("success") and result.get("ocr_text"):
            result["phishing_score"] = self._calculate_phishing_score(result)

        return result

    def parse_multiple(self, image_paths: List[str], prompt: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parse multiple images.

        Args:
            image_paths: List of image paths
            prompt: Optional custom prompt for all images

        Returns:
            List of parsed image dictionaries
        """
        results = []

        for image_path in image_paths:
            if prompt:
                result = self.parse_image(image_path, prompt)
            else:
                result = self.parse_image(image_path)
            results.append(result)

        logger.info("images_parsed_multiple", total=len(image_paths), successful=sum(1 for r in results if r.get("success")))
        return results

    def _detect_fraud_indicators(self, description: str) -> List[Dict[str, Any]]:
        """
        Detect fraud indicators in image description.

        Args:
            description: Image description text

        Returns:
            List of fraud indicators
        """
        indicators = []

        fraud_patterns = [
            (r'\b(urgent|immediate|suspended|locked|verify)\b', "urgency", "high"),
            (r'\b(click|download|install|update)\b', "action_request", "medium"),
            (r'\b(password|login|credential|account)\b', "credential_focus", "high"),
            (r'\b(prize|winner|reward|gift)\b', "reward_lure", "high"),
            (r'\b(security|warning|alert|error)\b', "fake_alert", "medium"),
            (r'\b(paypal|amazon|microsoft|apple|google)\b', "brand_impersonation", "high"),
        ]

        for pattern, indicator_type, severity in fraud_patterns:
            if re.search(pattern, description, re.IGNORECASE):
                indicators.append({
                    "type": indicator_type,
                    "severity": severity,
                    "matched_in": "description"
                })

        return indicators

    def _extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from OCR text.

        Args:
            text: OCR extracted text

        Returns:
            Dictionary of IOCs by type
        """
        iocs = {
            "urls": [],
            "ips": [],
            "emails": []
        }

        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        iocs["urls"] = list(set(re.findall(url_pattern, text)))

        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        iocs["ips"] = [
            ip for ip in potential_ips
            if all(0 <= int(octet) <= 255 for octet in ip.split("."))
        ]

        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["emails"] = list(set(re.findall(email_pattern, text)))

        return iocs

    def _calculate_phishing_score(self, analysis: Dict[str, Any]) -> int:
        """
        Calculate phishing likelihood score (0-100).

        Args:
            analysis: Image analysis results

        Returns:
            Phishing score
        """
        score = 0

        # Fraud indicators weight
        indicators = analysis.get("fraud_indicators", [])
        high_severity = sum(1 for i in indicators if i.get("severity") == "high")
        medium_severity = sum(1 for i in indicators if i.get("severity") == "medium")

        score += high_severity * 20
        score += medium_severity * 10

        # OCR IOCs weight
        if analysis.get("ocr_iocs"):
            iocs = analysis["ocr_iocs"]
            if iocs.get("urls"):
                score += 15
            if iocs.get("ips"):
                score += 10

        # Description keywords
        description = analysis.get("description", "").lower()
        if any(word in description for word in ["login", "password", "credential", "verify"]):
            score += 15

        return min(score, 100)

    def analyze_document_images(self, document_path: str) -> List[Dict[str, Any]]:
        """
        Extract and analyze images from a document (PDF).

        Args:
            document_path: Path to document

        Returns:
            List of analyzed images
        """
        try:
            import fitz  # PyMuPDF

            doc = fitz.open(document_path)
            results = []

            for page_num in range(len(doc)):
                page = doc[page_num]
                image_list = page.get_images()

                for img_index, img in enumerate(image_list):
                    try:
                        xref = img[0]
                        base_image = doc.extract_image(xref)
                        image_bytes = base_image["image"]

                        # Save temporarily
                        temp_path = f"/tmp/doc_image_{page_num}_{img_index}.png"
                        with open(temp_path, "wb") as f:
                            f.write(image_bytes)

                        # Analyze
                        analysis = self.parse_image(temp_path)
                        analysis["source_document"] = document_path
                        analysis["page_number"] = page_num + 1
                        analysis["image_index"] = img_index

                        results.append(analysis)

                    except Exception as e:
                        logger.warning("document_image_extraction_failed", page=page_num, index=img_index, error=str(e))

            doc.close()
            logger.info("document_images_analyzed", document=document_path, images=len(results))
            return results

        except ImportError:
            logger.error("pymupdf_not_available")
            return []
        except Exception as e:
            logger.error("document_image_analysis_failed", document=document_path, error=str(e))
            return []

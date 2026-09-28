"""
YOLOv8 object detector running an ONNX export (80 COCO classes).

Uses onnxruntime when installed (faster on CPU, can use CUDA), otherwise
OpenCV's DNN module. To use your own fine-tuned model:

    pip install ultralytics
    yolo export model=best.pt format=onnx imgsz=640
    MODEL_PATH=best.onnx  (and update PERSON_CLASSES / BAG_CLASSES in config.py)
"""
import cv2
import numpy as np

COCO = ["person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat",
        "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat", "dog",
        "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack", "umbrella",
        "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball", "kite",
        "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket", "bottle",
        "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple", "sandwich",
        "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair", "couch",
        "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse", "remote",
        "keyboard", "cell phone", "microwave", "oven", "toaster", "sink", "refrigerator", "book",
        "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush"]


class Detector:
    def __init__(self, model_path, input_size=640, conf=0.35, nms=0.45, keep_classes=None):
        self.size = input_size
        self.conf = conf
        self.nms = nms
        self.keep = set(keep_classes) if keep_classes else None
        self.backend = None
        try:
            import onnxruntime as ort
            providers = [p for p in ("CUDAExecutionProvider", "CPUExecutionProvider")
                         if p in ort.get_available_providers()]
            self.sess = ort.InferenceSession(model_path, providers=providers)
            self.input_name = self.sess.get_inputs()[0].name
            self.backend = "onnxruntime:" + providers[0]
        except ImportError:
            self.net = cv2.dnn.readNetFromONNX(model_path)
            self.backend = "opencv-dnn"

    def _letterbox(self, img):
        h, w = img.shape[:2]
        r = self.size / max(h, w)
        nw, nh = int(round(w * r)), int(round(h * r))
        resized = cv2.resize(img, (nw, nh), interpolation=cv2.INTER_LINEAR)
        canvas = np.full((self.size, self.size, 3), 114, dtype=np.uint8)
        dx, dy = (self.size - nw) // 2, (self.size - nh) // 2
        canvas[dy:dy + nh, dx:dx + nw] = resized
        return canvas, r, dx, dy

    def __call__(self, frame, tiles=1):
        """
        Returns list of dicts: {cls, name, conf, box:[x1,y1,x2,y2]} in frame pixels.
        tiles=2 also runs the model on a 2x2 grid of overlapping crops, which finds the
        small people/bags you get from a drone at 25-40 m (about 5x the compute).
        """
        if tiles <= 1:
            return self._detect(frame)
        H, W = frame.shape[:2]
        dets = self._detect(frame)
        tw, th = int(W / tiles * 1.2), int(H / tiles * 1.2)
        for i in range(tiles):
            for j in range(tiles):
                x0 = min(int(i * W / tiles - 0.1 * W / tiles), W - tw) if i else 0
                y0 = min(int(j * H / tiles - 0.1 * H / tiles), H - th) if j else 0
                x0, y0 = max(0, x0), max(0, y0)
                for d in self._detect(frame[y0:y0 + th, x0:x0 + tw]):
                    b = d["box"]
                    d["box"] = [b[0] + x0, b[1] + y0, b[2] + x0, b[3] + y0]
                    dets.append(d)
        if not dets:
            return []
        xywh = [[d["box"][0], d["box"][1], d["box"][2] - d["box"][0], d["box"][3] - d["box"][1]] for d in dets]
        idx = cv2.dnn.NMSBoxesBatched(xywh, [d["conf"] for d in dets], [d["cls"] for d in dets],
                                      self.conf, self.nms)
        return [dets[i] for i in np.array(idx).flatten()]

    def _detect(self, frame):
        img, r, dx, dy = self._letterbox(frame)
        blob = cv2.dnn.blobFromImage(img, 1 / 255.0, swapRB=True)
        if self.backend.startswith("onnxruntime"):
            out = self.sess.run(None, {self.input_name: blob})[0]
        else:
            self.net.setInput(blob)
            out = self.net.forward()
        pred = out[0].T                      # (8400, 84): cx, cy, w, h, 80 class scores
        scores = pred[:, 4:]
        cls = scores.argmax(1)
        conf = scores[np.arange(len(cls)), cls]
        m = conf >= self.conf
        if self.keep is not None:
            m &= np.isin(cls, list(self.keep))
        pred, cls, conf = pred[m], cls[m], conf[m]
        if len(pred) == 0:
            return []
        cx, cy, bw, bh = pred[:, 0], pred[:, 1], pred[:, 2], pred[:, 3]
        x1 = (cx - bw / 2 - dx) / r
        y1 = (cy - bh / 2 - dy) / r
        boxes_xywh = np.stack([x1, y1, bw / r, bh / r], 1)
        idx = cv2.dnn.NMSBoxesBatched(boxes_xywh.tolist(), conf.tolist(), cls.tolist(),
                                      self.conf, self.nms)
        H, W = frame.shape[:2]
        dets = []
        for i in np.array(idx).flatten():
            x, y, w, h = boxes_xywh[i]
            dets.append({
                "cls": int(cls[i]),
                "name": COCO[int(cls[i])],
                "conf": float(conf[i]),
                "box": [float(max(0.0, x)), float(max(0.0, y)), float(min(W - 1.0, x + w)), float(min(H - 1.0, y + h))],
            })
        return dets

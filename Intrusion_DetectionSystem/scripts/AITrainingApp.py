from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtGui import QIcon, QCloseEvent

class AITrainingApp(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setWindowTitle("AI 에이전트 학습")
        layout = QVBoxLayout()
        label = QLabel("AI 에이전트 학습 화면입니다.")
        layout.addWidget(label)
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.clicked.connect(self.return_to_main)
        back_button.setFixedSize(30, 30)  # 데이터 전처리 화면의 크기에 맞춤
        layout.addWidget(back_button)
        self.setLayout(layout)

    def closeEvent(self, event: QCloseEvent):
        self.parent_app.show_main_screen()
        event.accept()

    def return_to_main(self):
        self.parent_app.show_main_screen()
        self.close() 
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication


def point_size_to_pixels(point_size):
    """
    Переводит размер шрифта из pointSize() в пиксели.
    """
    # Получаем текущий DPI из приложения
    app = QApplication.instance() or QApplication([])
    screen = app.primaryScreen()
    dpi = screen.logicalDotsPerInch()

    # Формула перевода: pixels = (points * dpi) / 72
    return int((point_size * dpi) / 72)


if __name__ == '__main__':
    # Пример: Получение размера шрифта
    font = QFont("Arial", 12)  # Установлен размер шрифта в поинтах
    point_size = font.pointSize()
    pixel_size = point_size_to_pixels(point_size)

    print(f"Размер шрифта: {point_size} поинтов = {pixel_size} пикселей")

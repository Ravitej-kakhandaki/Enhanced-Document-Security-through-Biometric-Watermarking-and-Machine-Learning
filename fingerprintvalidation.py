import cv2
import numpy as np
import matplotlib.pyplot as plt
from skimage.feature import canny
from skimage.morphology import skeletonize

# Preprocessing function
def preprocess_fingerprint(image_path):
    # Load the image in grayscale
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)

    # Apply Gaussian blur to remove noise
    image = cv2.GaussianBlur(image, (5, 5), 0)

    # Threshold the image (binary conversion)
    _, thresholded = cv2.threshold(image, 100, 255, cv2.THRESH_BINARY_INV)

    # Display the preprocessed image
    plt.imshow(thresholded, cmap='gray')
    plt.title('Preprocessed Fingerprint')
##    plt.show()

    return thresholded

# Feature extraction function using edge detection and skeletonization
def extract_minutiae(image):
    # Apply edge detection (Canny)
    edges = canny(image / 255.0, sigma=1.0)  # Normalize to [0, 1]

    # Skeletonize the fingerprint (reduces it to a single-pixel wide representation)
    skeleton = skeletonize(edges)

    # Display the skeletonized fingerprint
    plt.imshow(skeleton, cmap='gray')
    plt.title('Skeletonized Fingerprint')
##    plt.show()

    # Find minutiae points (ridge endings and bifurcations)
    minutiae_points = []
    rows, cols = skeleton.shape
    for i in range(1, rows-1):
        for j in range(1, cols-1):
            # If the pixel is part of the skeleton
            if skeleton[i, j] == 1:
                # Count the number of neighbors in the 3x3 window
                neighbors = np.sum(skeleton[i-1:i+2, j-1:j+2]) - 1  # exclude the center pixel
                if neighbors == 1:  # Ridge ending
                    minutiae_points.append(('ending', i, j))
                elif neighbors > 2:  # Bifurcation
                    minutiae_points.append(('bifurcation', i, j))

    # Display minutiae points on the skeletonized image
    for minutiae in minutiae_points:
        if minutiae[0] == 'ending':
            color = (0, 0, 255)  # Red for endings
        else:
            color = (0, 255, 0)  # Green for bifurcations
        cv2.circle(image, (minutiae[2], minutiae[1]), 2, color, -1)

    plt.imshow(image, cmap='gray')
    plt.title('Minutiae Points')
##    plt.show()

    return minutiae_points

# Function to compare two fingerprint images based on minutiae matching
def match_fingerprints(minutiae1, minutiae2):
    # Simple matching: Count the number of common minutiae points
    matching_points = 0
    for m1 in minutiae1:
        for m2 in minutiae2:
            # Compare if minutiae types and coordinates are the same
            if m1[0] == m2[0] and abs(m1[1] - m2[1]) < 5 and abs(m1[2] - m2[2]) < 5:
                matching_points += 1

    print(f"Matching minutiae points: {matching_points}")
    if matching_points > 500:  # You can adjust this threshold based on your needs
        print("Fingerprints match!")
        return 'Live'
    else:
        print("Fingerprints do not match.")
        return 'Fake'

# Main function to run the fingerprint validation
def FingerprintRecognition(image_path_1, image_path_2):
    # Preprocess both images
    fingerprint_image_1 = preprocess_fingerprint(image_path_1)
    fingerprint_image_2 = preprocess_fingerprint(image_path_2)

    # Extract minutiae from both images
    minutiae1 = extract_minutiae(fingerprint_image_1)
    minutiae2 = extract_minutiae(fingerprint_image_2)

    # Perform fingerprint matching based on minutiae points
    res = match_fingerprints(minutiae1, minutiae2)
    return res
#include <stdio.h>


void quicksort(long arr[], int arr_size) {
    
   
    if (arr_size>1) {
        //int pi = partition(arr, low, high);
        int high=arr_size-1;
        long pivot = arr[high];
        int i = -1;
        
        for (int j = 0; j < high; j++) {
            if (arr[j] <= pivot) {
                i++;
                //swap(&arr[i], &arr[j]);
                if(i!=j){
                    long tmp=arr[i];
                    arr[i]=arr[j];
                    arr[j]=tmp;
                }
            }
        }
        
        i++;
        arr[high]=arr[i];
        arr[i]=pivot;
        

        //////////////////////////////////////
        quicksort(arr, i);
        quicksort(arr+i+1, high-i);
    }
}





// void quicksort(int arr[], int low, int high) {
//     if (low < high) {
//         int pi = partition(arr, low, high);
//         quicksort(arr, low, pi - 1);
//         quicksort(arr, pi + 1, high);
//     }
// }

int main() {
    int n;
    // printf("Enter the size of the array: ");
    scanf("%d", &n);

    long arr[n];
    // printf("Enter %d elements:\n", n);
    for (int i = 0; i < n; i++) {
        scanf("%ld", &arr[i]);
    }

    printf("Unsorted array: ");
    for (int i = 0; i < n; i++) {
        printf("%ld ", arr[i]);
    }
    printf("\n");
    
    quicksort(arr, n);
    
    printf("Sorted array: ");
    for (int i = 0; i < n; i++) {
        printf("%ld ", arr[i]);
    }
    printf("\n");
    
    return 0;
}

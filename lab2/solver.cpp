#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
using namespace std;

void recursive_search (string path,string magic_num)
{
  
    if(filesystem::is_symlink(path))
        return;

    for (const auto & entry : filesystem::directory_iterator(path)){
    
        if(filesystem::is_directory(entry.path())){

            recursive_search(entry.path(), magic_num);

        }
        else{
            
            std::cerr << entry.path() << std::endl;
            ifstream file(entry.path());
            string line;
            while(getline(file, line)){
                cerr << line <<endl;
                if( line.find( magic_num, 0 ) != string::npos ){
                    string path = entry.path();
                    cout << path << endl;
                }
            }
            file.close();

        }
        
    }

}



int main(int argc,char **argv)
{
   string path=argv[1];
   string magic_num=argv[2];
   
   if(argc==3)
   {
     recursive_search(path,magic_num);
   }else
   {
     cout<<"error : expected two parameter";
   }
   
   return 0;

}
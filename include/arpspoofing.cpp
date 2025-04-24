#include "arpspoofing.h"

using namespace std;


void ArpSpoofing::RecvPacketThreadFunc() {
    while(1) {
        usleep(10);

        switch(this->status_) {
            case STATUS_INIT: {
                break;
            }
            case STATUS_PAUSE: {
                unique_lock<mutex> t(this->mtx_);
                this->cv_.wait(t);
                t.unlock();
                break;
            }
            case STATUS_PLAY: {
                unique_lock<mutex> t(this->mtx_);
                if(this->ReadPacket(this->GetCurrentInterface())) {

                }
                t.unlock();
                break;
            }
            case STATUS_END: {
                goto END;
                break;
            }
        defualt:
            break;
        }
    }
END:
    return;
}


ArpSpoofing::ArpSpoofing() {

}

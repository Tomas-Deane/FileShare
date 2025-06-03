#ifndef SERVICES_H
#define SERVICES_H

#include <memory>
#include "inetworkmanager.h"
#include "icryptoservice.h"
#include "networkmanager.h"
#include "cryptoservice.h"
#include "authcontroller.h"
#include "profilecontroller.h"
#include "filecontroller.h"
#include "verifycontroller.h"
#include "sharecontroller.h"

struct Services {
    std::unique_ptr<INetworkManager>   net;
    std::unique_ptr<ICryptoService>    cs;

    // all controllers talk only in terms of the interfaces above:
    std::unique_ptr<AuthController>    auth;
    std::unique_ptr<ProfileController> profile;
    std::unique_ptr<FileController>    file;
    std::unique_ptr<VerifyController>  verify;
    std::unique_ptr<ShareController>   share;

    Services()
    {

        net = std::make_unique<NetworkManager>();
        cs  = std::make_unique<CryptoService>();

        auth    = std::make_unique<AuthController>(net.get(), cs.get());
        profile = std::make_unique<ProfileController>(net.get(), auth.get(), cs.get());
        file    = std::make_unique<FileController>(net.get(), auth.get(), cs.get());
        verify  = std::make_unique<VerifyController>(net.get(), auth.get(), cs.get());
        share   = std::make_unique<ShareController>(net.get(), auth.get(), cs.get());
    }
};

#endif // SERVICES_H
